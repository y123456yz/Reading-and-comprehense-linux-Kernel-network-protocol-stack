/*
 * net/sched/sch_fifo.c	The simplest FIFO queue.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

/* 1 band FIFO pseudo-"scheduler" */

//私有数据，也就是fifo的参数
struct fifo_sched_data //该结构紧跟在Qdisc后面，见pfifo_enqueue->struct fifo_sched_data *q = qdisc_priv(sch);
{
	u32 limit; //默认为(MTU+ETH(14字节))*net_device.tx_queue_len  ，见fifo_init
};

static int bfifo_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct fifo_sched_data *q = qdisc_priv(sch);

	if (likely(sch->qstats.backlog + qdisc_pkt_len(skb) <= q->limit))
		return qdisc_enqueue_tail(skb, sch);

	return qdisc_reshape_fail(skb, sch);
}

static int pfifo_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct fifo_sched_data *q = qdisc_priv(sch);

	if (likely(skb_queue_len(&sch->q) < q->limit)) //直接入qdisc->q队列，所以是典型的先进先出
		return qdisc_enqueue_tail(skb, sch);

	return qdisc_reshape_fail(skb, sch); //如果队列规则中限定的SKB达到上限了，则直接丢弃该SKB
}

static int pfifo_tail_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct sk_buff *skb_head;
	struct fifo_sched_data *q = qdisc_priv(sch);

	if (likely(skb_queue_len(&sch->q) < q->limit))
		return qdisc_enqueue_tail(skb, sch);

	/* queue full, remove one skb to fulfill the limit */
	skb_head = qdisc_dequeue_head(sch);
	sch->bstats.bytes -= qdisc_pkt_len(skb_head);
	sch->bstats.packets--;
	sch->qstats.drops++;
	kfree_skb(skb_head);

	qdisc_enqueue_tail(skb, sch);

	return NET_XMIT_CN;
}
//见bfifo_qdisc_ops     fifo方式是简单的限速方式，允许Qdisc 的skb队列中最多容纳的SKB包个数，如果包来的时候该SKB队列中的包个数达到上限，则直接丢弃
static int fifo_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct fifo_sched_data *q = qdisc_priv(sch);

	if (opt == NULL) {
		u32 limit = qdisc_dev(sch)->tx_queue_len ? : 1;

		if (sch->ops == &bfifo_qdisc_ops)
			limit *= psched_mtu(qdisc_dev(sch));

		q->limit = limit;
	} else {
		struct tc_fifo_qopt *ctl = nla_data(opt);

		if (nla_len(opt) < sizeof(*ctl))
			return -EINVAL;

		q->limit = ctl->limit;
	}

	return 0;
}

static int fifo_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct fifo_sched_data *q = qdisc_priv(sch);
	struct tc_fifo_qopt opt = { .limit = q->limit };

	NLA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);
	return skb->len;

nla_put_failure:
	return -1;
}

/*pfifo_fast_ops pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops prio_class_ops这几个都为出口，ingress_qdisc_ops为入口 */
struct Qdisc_ops pfifo_qdisc_ops {//__read_mostly = {
	.id		=	"pfifo",  //如果队列规则中限定的SKB达到上限了，则直接丢弃该SKB,这个上限为下面的priv_size中的limit进行配置
	.priv_size	=	sizeof(struct fifo_sched_data),
	.enqueue	=	pfifo_enqueue, ////直接入qdisc->q队列，所以是典型的先进先出
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.drop		=	qdisc_queue_drop,
	.init		=	fifo_init,
	.reset		=	qdisc_reset_queue,
	.change		=	fifo_init,
	.dump		=	fifo_dump,
	.owner		=	THIS_MODULE,
};
EXPORT_SYMBOL(pfifo_qdisc_ops);

struct Qdisc_ops bfifo_qdisc_ops {//__read_mostly = {  fifo方式是简单的限速方式，允许Qdisc 的skb队列中最多容纳的SKB包个数，如果包来的时候该SKB队列中的包个数达到上限，则直接丢弃
	.id		=	"bfifo",
	.priv_size	=	sizeof(struct fifo_sched_data),
	.enqueue	=	bfifo_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.drop		=	qdisc_queue_drop,
	.init		=	fifo_init,
	.reset		=	qdisc_reset_queue,
	.change		=	fifo_init,
	.dump		=	fifo_dump,
	.owner		=	THIS_MODULE,
};
EXPORT_SYMBOL(bfifo_qdisc_ops);

struct Qdisc_ops pfifo_head_drop_qdisc_ops {//__read_mostly = {  fifo方式是简单的限速方式，允许Qdisc 的skb队列中最多容纳的SKB包个数
	.id		=	"pfifo_head_drop",
	.priv_size	=	sizeof(struct fifo_sched_data),
	.enqueue	=	pfifo_tail_enqueue,
	.dequeue	=	qdisc_dequeue_head,
	.peek		=	qdisc_peek_head,
	.drop		=	qdisc_queue_drop_head,
	.init		=	fifo_init,
	.reset		=	qdisc_reset_queue,
	.change		=	fifo_init,
	.dump		=	fifo_dump,
	.owner		=	THIS_MODULE,
};

/* Pass size change message down to embedded FIFO */
int fifo_set_limit(struct Qdisc *q, unsigned int limit)
{
	struct nlattr *nla;
	int ret = -ENOMEM;

	/* Hack to avoid sending change message to non-FIFO */
	if (strncmp(q->ops->id + 1, "fifo", 4) != 0)
		return 0;

	nla = kmalloc(nla_attr_size(sizeof(struct tc_fifo_qopt)), GFP_KERNEL);
	if (nla) {
		nla->nla_type = RTM_NEWQDISC;
		nla->nla_len = nla_attr_size(sizeof(struct tc_fifo_qopt));
		((struct tc_fifo_qopt *)nla_data(nla))->limit = limit;

		ret = q->ops->change(q, nla);
		kfree(nla);
	}
	return ret;
}
EXPORT_SYMBOL(fifo_set_limit);

struct Qdisc *fifo_create_dflt(struct Qdisc *sch, struct Qdisc_ops *ops,
			       unsigned int limit)
{
	struct Qdisc *q;
	int err = -ENOMEM;

	q = qdisc_create_dflt(qdisc_dev(sch), sch->dev_queue,
			      ops, TC_H_MAKE(sch->handle, 1));
	if (q) {
		err = fifo_set_limit(q, limit);
		if (err < 0) {
			qdisc_destroy(q);
			q = NULL;
		}
	}

	return q ? : ERR_PTR(err);
}
EXPORT_SYMBOL(fifo_create_dflt);

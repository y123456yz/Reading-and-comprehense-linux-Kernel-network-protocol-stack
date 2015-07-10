/*
 * net/sched/sch_prio.c	Simple 3-band priority "scheduler".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * Fixes:       19990609: J Hadi Salim <hadi@nortelnetworks.com>:
 *              Init --  EINVAL when opt undefined
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

/* 优先级队列规定的band为16个,参考TC流量控制实现分析(初步)-图3  建立”prio”类型的根流控对象_2 */   //详细理解也可以参考<<LINUX高级路由和流量控制>>
/*
现在假设要发送一个skb->priority值是8的数据包，发送流程如下：
1.      使用网卡的根流控对象的入队函数将数据包入队
2.      由于未设置过滤器，则直接根据数据包的skb->priority=8找到对应的带是0，则将数据包加入第一个pfifo流控对象。
3.      调用pfifo流控对象的入队函数，将数据包加入对象中的数据包队列。
4.      调用qdisc_run()启动根流控对象。
5.      调用根流控对象的出队函数，函数内先选择第一个pfifo流控对象并调用其出队函数选择一个数据包，出队函数返回，如果第一个pfifo流控对象为空，选择第二个pfifo流控对象并调用其出队函数选择一个数据包，直到找到一个数据包。
6.      发送5找到的数据包。
7.      只要时间允许且流控对象不为空，就一直循环5，6的过程。
*/
//    使用int register_qdisc(struct Qdisc_ops *qops)注册对象类型。
//    使用int register_tcf_proto_ops(struct tcf_proto_ops *ops)注册过滤器类型。

/*
进入出口流控的函数为dev_queue_xmit(); 如果是入口流控, 数据只是刚从网卡设备中收到, 还未交到网络上层处理, 不过网卡的入口流控不是必须的,  增加一个入口流控队列# tc qdisc add dev eth0 ingress
缺省情况下并不进行流控，进入入口流控函数为ing_filter()函数，该函数被skb_receive_skb()调用。
*/ //获取引用层参数的地方在prio_tune，该结构初始化在prio_tune
struct prio_sched_data //内核空间和应用层通过netlink交互接收数据过程，见函数pktsched_init，tc qdisc命令就是在这里面确定
{//tc qdisc add dev eth0 root handle 22 prio band 4 priomap 3 3 2 2 1 2 0 0 1 1 1 1 1 1 1 1
   //band表示该qdisc最多有几个频道，其子qdisc的band参数不能超过改值，超过了则返回错(tc qdisc add dev eth0 parent 22:8 handle 33,8不能超过父Qdisc的band)，见prio_get
	int bands;//就是上面tc命令中的4，表示用的是prio2band中的前面4个band(频道) //bands参数取值范围2-16，见prio_tune 如果不设置该参数，默认值为3，见应用层prio_parse_opt
	struct tcf_proto *filter_list; //tc filter添加过滤器的时候用到 图形化参考TC流量控制实现分析(初步) //里面的每个元素的最大指为前面的bands 见prio_tune
	u8  prio2band[TC_PRIO_MAX+1]; //priomap后面的参数。prio2band映射，默认映射只映射前3个带，如果使用prio子对象在第4个带，则需要添加过滤器，如tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4

    //通过tc qdisc add dev eth0 parent 22:8 handle 33中的22:8来进行分类，从而选出应该把handle为33的子队列规程添加到父队列规程的的几个queue[i]中
    //默认指向的是pfifo_qdisc_ops,见qdisc_create -> prio_init -> prio_tune -> qdisc_create_dflt，也就是说在创建分类队列规程的时候，系统会默认给分类信息数组指定pfifo无类队列规程，也就是queue[]默认指向的是pfifo_fast无类队列规程
	struct Qdisc *queues[TCQ_PRIO_BANDS];//入队，出队相关，prio队列规则ops为pfifo_qdisc_ops，其他还有tbf_qdisc_ops sfq_qdisc_ops等， 
};

static struct Qdisc *
prio_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	u32 band = skb->priority;
	struct tcf_result res;
	int err;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	if (TC_H_MAJ(skb->priority) != sch->handle) {
		err = tc_classify(skb, q->filter_list, &res); //通过skb和过滤器配合起来，选择出对应的分类数组queues[]中的具体哪一个queues[i]
#ifdef CONFIG_NET_CLS_ACT
		switch (err) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			return NULL;
		}
#endif
		if (!q->filter_list || err < 0) {
			if (TC_H_MAJ(band))
				band = 0;
		
			return q->queues[q->prio2band[band&TC_PRIO_MAX]];//
		}
		band = res.classid;
	}
	band = TC_H_MIN(band) - 1;
	if (band >= q->bands) //如果SKB的priority比创建qdisc的band频道大，则直接使用第0个频道的
		return q->queues[q->prio2band[0]];

    //如果分类队列规定没有分类出无类的子类队列规定，则queues[]默认指向的是&noop_qdisc;见prio_init，也就是说如果分类队列规定没有包含无类队列规定，则SKB会通过noop_qdisc直接丢弃
	return q->queues[band];//如果skb->priority在qdisc所在的bands范围内，直接使用q->queues[band]，否则使用q->queues[q->prio2band[0]]
}

//出方向入队在dev_queue_xmit  sch为跟队列规程
//qdisc_enqueue -> prio_enqueue ->pfifo_enqueue
static int
prio_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct Qdisc *qdisc;
	int ret;

    //通过过滤器来选择使用那个分支队列规程入队
	qdisc = prio_classify(skb, sch, &ret);//按照skb->priority对跟队列规程进行分类，选择使用跟队列规程中的哪一个后续子qdisc
#ifdef CONFIG_NET_CLS_ACT
	if (qdisc == NULL) { //例如创建的是分类队列规程，没有为其创建子队列规程，并启用了分类信息CONFIG_NET_CLS_ACT，则直接丢弃

		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
#endif

	ret = qdisc_enqueue(skb, qdisc); //递归入队
	if (ret == NET_XMIT_SUCCESS) {
		sch->bstats.bytes += qdisc_pkt_len(skb);
		sch->bstats.packets++;
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}
	if (net_xmit_drop_count(ret))
		sch->qstats.drops++;
	return ret;
}

static struct sk_buff *prio_peek(struct Qdisc *sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < q->bands; prio++) {
		struct Qdisc *qdisc = q->queues[prio];
		struct sk_buff *skb = qdisc->ops->peek(qdisc);
		if (skb)
			return skb;
	}
	return NULL;
}

//__qdisc_run -> qdisc_restart -> dequeue_skb -> prio_dequeue(这里面有个递归调用过程) -> qdisc_dequeue_head
static struct sk_buff *prio_dequeue(struct Qdisc* sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	for (prio = 0; prio < q->bands; prio++) {
		struct Qdisc *qdisc = q->queues[prio];
		struct sk_buff *skb = qdisc->dequeue(qdisc);//一次遍历找叶子上的无类队列规程，就是找叶子qdisc,这是地柜调用，实际上是找一颗数的最左边叶子，然后找右边叶子
		if (skb) {
			sch->q.qlen--;
			return skb;
		}
	}
	return NULL;

}

static unsigned int prio_drop(struct Qdisc* sch)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;
	unsigned int len;
	struct Qdisc *qdisc;

	for (prio = q->bands-1; prio >= 0; prio--) {
		qdisc = q->queues[prio];
		if (qdisc->ops->drop && (len = qdisc->ops->drop(qdisc)) != 0) {
			sch->q.qlen--;
			return len;
		}
	}
	return 0;
}


static void
prio_reset(struct Qdisc* sch)
{
	int prio;
	struct prio_sched_data *q = qdisc_priv(sch);

	for (prio=0; prio<q->bands; prio++)
		qdisc_reset(q->queues[prio]);
	sch->q.qlen = 0;
}

static void
prio_destroy(struct Qdisc* sch)
{
	int prio;
	struct prio_sched_data *q = qdisc_priv(sch);

	tcf_destroy_chain(&q->filter_list);
	for (prio=0; prio<q->bands; prio++)
		qdisc_destroy(q->queues[prio]);
}

static int prio_tune(struct Qdisc *sch, struct nlattr *opt)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct tc_prio_qopt *qopt;
	int i;

	if (nla_len(opt) < sizeof(*qopt))
		return -EINVAL;
	qopt = nla_data(opt);

	if (qopt->bands > TCQ_PRIO_BANDS || qopt->bands < 2)
		return -EINVAL;

	for (i=0; i<=TC_PRIO_MAX; i++) {
		if (qopt->priomap[i] >= qopt->bands)
			return -EINVAL;
	}

	sch_tree_lock(sch);
	q->bands = qopt->bands;
	memcpy(q->prio2band, qopt->priomap, TC_PRIO_MAX+1);

	for (i=q->bands; i<TCQ_PRIO_BANDS; i++) {
		struct Qdisc *child = q->queues[i];
		q->queues[i] = &noop_qdisc; 
		if (child != &noop_qdisc) {
			qdisc_tree_decrease_qlen(child, child->q.qlen);
			qdisc_destroy(child);
		}
	}
	sch_tree_unlock(sch);

	for (i=0; i<q->bands; i++) {
		if (q->queues[i] == &noop_qdisc) {
			struct Qdisc *child, *old; // fifo方式是简单的限速方式，允许Qdisc 的skb队列中最多容纳的SKB包个数，如果包来的时候该SKB队列中的包个数达到上限，则直接丢弃
			child = qdisc_create_dflt(qdisc_dev(sch), sch->dev_queue,
						  &pfifo_qdisc_ops,
						  TC_H_MAKE(sch->handle, i + 1));//默认是创建pfifo Qdisc队列规程，//初始化为这个，然后在创建子队列规程的时候该值指向对应的子Qdisc中，见tc流量控制/TC流量控制实现分析（初步）
			if (child) {
				sch_tree_lock(sch);
				old = q->queues[i];
				q->queues[i] = child;

				if (old != &noop_qdisc) {
					qdisc_tree_decrease_qlen(old,
								 old->q.qlen);
					qdisc_destroy(old);
				}
				sch_tree_unlock(sch);
			}
		}
	}
	return 0;
}

//如果tc add qdisc的时候没有指定使用哪种队列规定，如prio htb tbq cbf等，则默认给qdisc的私有分类信息组创建pfifo_fast无类队列规定，见prio_tune
static int prio_init(struct Qdisc *sch, struct nlattr *opt) //qdisc_create中调用
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int i;

	for (i=0; i<TCQ_PRIO_BANDS; i++)
		q->queues[i] = &noop_qdisc;

	if (opt == NULL) { //如果没有指定prio的参数band，则直接返回错误，参数不对
		return -EINVAL;
	} else {
		int err;

		if ((err= prio_tune(sch, opt)) != 0)
			return err;
	}
	return 0;
}

static int prio_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_prio_qopt opt;

	opt.bands = q->bands;
	memcpy(&opt.priomap, q->prio2band, TC_PRIO_MAX+1);

	NLA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

/*
sch:父Qdisc
arg:tc qdisc add dev eth0 parent 22:8 handle 33中的8，表示使用父队列规程的第8频道
new:新的handle为33的qdisc
arg为通过22:8中的8从prio_get选出的分类信息数组中的那一个分类信息
*/
static int prio_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->queues[band];
	q->queues[band] = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	return 0;
}

static struct Qdisc *
prio_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	return q->queues[band];
}

/* 父Qdisc  父handle */
//tc qdisc add dev eth0 parent 22:4 handle 33 prio bands 5  p为22对应的队列规程 q为33对应的队列规程 ,见qdisc_graft
static unsigned long prio_get(struct Qdisc *sch, u32 classid) //prio_class_ops    走到这里的时候classid中的A:B中的B肯定大于0，否则在外层就返回错了，因为实际用的时候B会-1
{
	struct prio_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid); //对应parent 22:4中的4

//假如父Qdisc设置的bands频道为7，而tc qdisc add dev eth0 parent 22:8 handle 33，22:8表示使用父Qdisc的第8个频道，但父Qdisc一共才7个频道，所以越界了，返回0，于是在qdisc_graft中报错返回
	if (band - 1 >= q->bands) //见qdisc_graft，如果返回0，则直接从qdisc_graft退出，反错
		return 0;
	return band;
}

static unsigned long prio_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{
	return prio_get(sch, classid);
}


static void prio_put(struct Qdisc *q, unsigned long cl)
{
}

static int prio_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb,
			   struct tcmsg *tcm)
{
	struct prio_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = q->queues[cl-1]->handle;
	return 0;
}

static int prio_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;

	cl_q = q->queues[cl - 1];
	cl_q->qstats.qlen = cl_q->q.qlen;
	if (gnet_stats_copy_basic(d, &cl_q->bstats) < 0 ||
	    gnet_stats_copy_queue(d, &cl_q->qstats) < 0)
		return -1;

	return 0;
}

static void prio_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	int prio;

	if (arg->stop)
		return;

	for (prio = 0; prio < q->bands; prio++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, prio+1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static struct tcf_proto ** prio_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct prio_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return &q->filter_list;
}

//prio对应prio_class_ops htb对应htb_class_ops cbq对应cbq_class_ops等等
//qdisc_graft函数中会调用下面的相关函数
//skb入队的时候通过下面的函数选择使用prio_sched_data -> queues[]中的那个queues入队，出队的时候一样
static const struct Qdisc_class_ops prio_class_ops = {
	.graft		=	prio_graft,
	.leaf		=	prio_leaf,
	.get		=	prio_get, //参考qdisc_graf，选择使用Qdisc_class_ops分类信息数组中的那个信息，通过这个获取选择出的关键信息，然后使用该信息域graft配合使用
	.put		=	prio_put,
	.walk		=	prio_walk,
	.tcf_chain	=	prio_find_tcf,
	.bind_tcf	=	prio_bind,
	.unbind_tcf	=	prio_put,
	.dump		=	prio_dump_class,
	.dump_stats	=	prio_dump_class_stats,
};

/*
                                    
*/

/*pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops prio_class_ops这几个都为出口，ingress_qdisc_ops为入口 */
static struct Qdisc_ops prio_qdisc_ops ;//__read_mostly = {          prio的跟不支持在跟下面创建class，见tc_ctl_tclass
	.next		=	NULL,
	.cl_ops		=	&prio_class_ops,  //prio分类规则不能创建分类信息，不能tc class add， 因为私有数据部分已经提前创建好了分类数组
	.id		=	"prio",
	.priv_size	=	sizeof(struct prio_sched_data),
	.enqueue	=	prio_enqueue, //dev_xmit_queue一直下去调用
	.dequeue	=	prio_dequeue, //dequeue_skb中调用
	.peek		=	prio_peek,
	.drop		=	prio_drop,
	.init		=	prio_init, //分类的队列规则在初始化的时候会默认指向noop_qdisc   在qdisc_create中调用，如果
	.reset		=	prio_reset,
	.destroy	=	prio_destroy,
	.change		=	prio_tune,
	.dump		=	prio_dump,
	.owner		=	THIS_MODULE,
};

static int __init prio_module_init(void)
{
	return register_qdisc(&prio_qdisc_ops);
}

static void __exit prio_module_exit(void)
{
	unregister_qdisc(&prio_qdisc_ops);
}

module_init(prio_module_init)
module_exit(prio_module_exit)

MODULE_LICENSE("GPL");

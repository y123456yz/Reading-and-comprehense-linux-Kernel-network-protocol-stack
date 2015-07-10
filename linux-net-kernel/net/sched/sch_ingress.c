/* net/sched/sch_ingress.c - Ingress qdisc
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:     Jamal Hadi Salim 1999
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

/*
入口流控对象的私有数据是：
struct ingress_qdisc_data {
       struct tcf_proto      *filter_list;
};
入口流控对象只有入队函数，没有出队函数。
入队动作：先遍历过滤器，如果某个过滤器匹配，执行action（接收或者丢弃数据包），并将结果返回，最终根据这个返回的结果决定是否丢弃数据包。
*/
struct ingress_qdisc_data { //见ingress_qdisc_ops
	struct tcf_proto	*filter_list;
};

/* ------------------------- Class/flow operations ------------------------- */

static struct Qdisc *ingress_leaf(struct Qdisc *sch, unsigned long arg)
{
	return NULL;
}

static unsigned long ingress_get(struct Qdisc *sch, u32 classid)
{
	return TC_H_MIN(classid) + 1;
}

static unsigned long ingress_bind_filter(struct Qdisc *sch,
					 unsigned long parent, u32 classid)
{
	return ingress_get(sch, classid);
}

static void ingress_put(struct Qdisc *sch, unsigned long cl)
{
}

static void ingress_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
}

static struct tcf_proto **ingress_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);

	return &p->filter_list;
}

/* --------------------------- Qdisc operations ---------------------------- */

static int ingress_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);
	struct tcf_result res;
	int result;

	result = tc_classify(skb, p->filter_list, &res);

	sch->bstats.packets++;
	sch->bstats.bytes += qdisc_pkt_len(skb);
	switch (result) {
	case TC_ACT_SHOT:
		result = TC_ACT_SHOT;
		sch->qstats.drops++;
		break;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
		result = TC_ACT_STOLEN;
		break;
	case TC_ACT_RECLASSIFY:
	case TC_ACT_OK:
		skb->tc_index = TC_H_MIN(res.classid);
	default:
		result = TC_ACT_OK;
		break;
	}

	return result;
}

/* ------------------------------------------------------------- */

static void ingress_destroy(struct Qdisc *sch)
{
	struct ingress_qdisc_data *p = qdisc_priv(sch);

	tcf_destroy_chain(&p->filter_list);
}

static int ingress_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	nla_nest_end(skb, nest);
	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct Qdisc_class_ops ingress_class_ops = {
	.leaf		=	ingress_leaf,
	.get		=	ingress_get,
	.put		=	ingress_put,
	.walk		=	ingress_walk,
	.tcf_chain	=	ingress_find_tcf,
	.bind_tcf	=	ingress_bind_filter,
	.unbind_tcf	=	ingress_put,
};

/*
入口流控对象的私有数据是：
struct ingress_qdisc_data {
       struct tcf_proto      *filter_list;
};
入口流控对象只有入队函数，没有出队函数。
入队动作：先遍历过滤器，如果某个过滤器匹配，执行action（接收或者丢弃数据包），并将结果返回，最终根据这个返回的结果决定是否丢弃数据包。

int netif_receive_skb(struct sk_buff *skb)à
skb = handle_ing(skb, &pt_prev, &ret, orig_dev);à
ing_filter(skb)
增加一个入口流控队列# tc qdisc add dev eth0 ingress

*/
/*pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops prio_class_ops这几个都为出口，ingress_qdisc_ops为入口 */
static struct Qdisc_ops ingress_qdisc_ops { // __read_mostly = {
	.cl_ops		=	&ingress_class_ops,
	.id		=	"ingress",
	.priv_size	=	sizeof(struct ingress_qdisc_data),
	.enqueue	=	ingress_enqueue,////ingress通过ing_filter入队
	.destroy	=	ingress_destroy,
	.dump		=	ingress_dump,
	.owner		=	THIS_MODULE,
};

static int __init ingress_module_init(void)
{
	return register_qdisc(&ingress_qdisc_ops);
}

static void __exit ingress_module_exit(void)
{
	unregister_qdisc(&ingress_qdisc_ops);
}

module_init(ingress_module_init)
module_exit(ingress_module_exit)
MODULE_LICENSE("GPL");

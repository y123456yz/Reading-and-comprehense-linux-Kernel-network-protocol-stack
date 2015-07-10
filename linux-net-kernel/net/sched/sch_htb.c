/*
 * net/sched/sch_htb.c	Hierarchical token bucket, feed tree version
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Martin Devera, <devik@cdi.cz>
 *
 * Credits (in time order) for older HTB versions:
 *              Stef Coene <stef.coene@docum.org>
 *			HTB support at LARTC mailing list
 *		Ondrej Kraus, <krauso@barr.cz>
 *			found missing INIT_QDISC(htb)
 *		Vladimir Smelhaus, Aamer Akhter, Bert Hubert
 *			helped a lot to locate nasty class stall bug
 *		Andi Kleen, Jamal Hadi, Bert Hubert
 *			code review and helpful comments on shaping
 *		Tomasz Wrona, <tw@eter.tym.pl>
 *			created test case so that I was able to fix nasty bug
 *		Wilfried Weissmann
 *			spotted bug in dequeue code and helped with fix
 *		Jiri Fojtasek
 *			fixed requeue routine
 *		and many others. thanks.
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

/* HTB algorithm.
    Author: devik@cdi.cz
    ========================================================================
    HTB is like TBF with multiple classes. It is also similar to CBQ because
    it allows to assign priority to each class in hierarchy.
    In fact it is another implementation of Floyd's formal sharing.

    Levels:
    Each class is assigned level. Leaf has ALWAYS level 0 and root
    classes have level TC_HTB_MAXDEPTH-1. Interior nodes has level
    one less than their parent.
*/

static int htb_hysteresis = 0;// __read_mostly = 0; /* whether to use mode hysteresis for speedup */
#define HTB_VER 0x30011		/* major must be matched with number suplied by TC as version */

#if HTB_VER >> 16 != TC_HTB_PROTOVER
#error "Mismatched sch_htb.c and pkt_sch.h"
#endif

/* Module parameter and sysfs export */
module_param    (htb_hysteresis, int, 0640);
MODULE_PARM_DESC(htb_hysteresis, "Hysteresis mode, less CPU load, less accurate");

/* used internaly to keep status of single class */

/*
但HTB模式是HTB_CAN_SEND时, 表示是可以发送, 没有阻塞; 为HTB_CANT_SEND时表示阻塞, 根本不能
发送数据包了; 为HTB_MAY_BORROW时也属于阻塞状态, 但可以向其他类别借带宽来发送.
*/
enum htb_cmode {
    // 不能发送
	HTB_CANT_SEND,		/* class can't send and can't borrow */

	// 借带宽
	HTB_MAY_BORROW,		/* class can't send but may borrow */

	// 可发送
	HTB_CAN_SEND		/* class can send */
};

/*
但它是如何保证一棵n个结点的红黑树的高度始终保持在logn的呢？这就引出了红黑树的5个性质：

1.每个结点要么是红的要么是黑的。  
2.根结点是黑的。  
3.每个叶结点（叶结点即指树尾端NIL指针或NULL结点）都是黑的。  
4.如果一个结点是红的，那么它的两个儿子都是黑的。  
5.对于任意结点而言，其到叶结点树尾端NIL指针的每条路径都包含相同数目的黑结点。 
*/

/*
Usage: ... qdisc add ... htb [default N] [r2q N]
 default  minor id of class to which unclassified packets are sent {0}
 r2q      DRR quantums are computed as rate in Bps/r2q {10}
 debug    string of 16 numbers each 0-3 {0}

... class add ... htb rate R1 [burst B1] [mpu B] [overhead O]
                      [prio P] [slot S] [pslot PS]
                      [ceil R2] [cburst B2] [mtu MTU] [quantum Q]
 rate     rate allocated to this class (class can still borrow)
 burst    max bytes burst which can be accumulated during idle period {computed}
 mpu      minimum packet size used in rate computations
 overhead per-packet size overhead used in rate computations
 linklay  adapting to a linklayer e.g. atm
 ceil     definite upper class rate (no borrows) {rate}
 cburst   burst but for ceil {computed}
 mtu      max packet size we create rate map for {1600}
 prio     priority of leaf; lower are served first {0}
 quantum  how much bytes to serve from leaf at once {use r2q}
*/
/* interior & leaf nodes; props specific to leaves are marked L: */
//tc class add 两次后，会创建两个htb_class结构，这两个结构通过Qdisc_class_common -> hnode最终把htb_class加入到htb_sched(htb qdisc的私有数据)->clhash中，见htb_change_class -> qdisc_class_hash_insert
//htb_class经常用cl表示创建的tc class结构的地址，见htb_get
//参考<HTB介绍以及使用.doc>
struct htb_class {//htb_change_class中创建或者修改类，在创建htb子类的时候，会默认见一个pfifo_qdisc_ops叶子节点，真正SKB入队是如到该叶子节点的SKB队列上面
	struct Qdisc_class_common common; //通过这个和htb私有数据关联起来，见htb_change_class -> qdisc_class_hash_insert,连接到Qdisc_class_hash中的hash中
	/* general class parameters */
	struct gnet_stats_basic_packed bstats; // 字节数, 包数统计
	struct gnet_stats_queue qstats;// 队列信息统计
	struct gnet_stats_rate_est rate_est;// 速率统计, 字节率, 包率
	struct tc_htb_xstats xstats;	/* our special stats */// HTB统计信息, 借出, 借入, 令牌等参数
	int refcnt;		/* usage count of this class */// HTB类别引用计数  在创建class的时候初始化为1，见htb_change_class

	/* topology */
	// 在树中的层次, 0表示叶子节点, 根节点层次是TC_HTB_MAXDEPTH-1(7)
	int level;		/* our level (see above) */
	unsigned int children;

	//该结构和上面的common都能保证所有的htb_class(tc class add的时候创建的class信息节点)关联在一起
	struct htb_class *parent;	/* parent class */ //tc class add parent 5:2 classid 6: xxxx， parent为父class

    /*
    Usage: ... qdisc add ... htb [default N] [r2q N]
     default  minor id of class to which unclassified packets are sent {0}
     r2q      DRR quantums are computed as rate in Bps/r2q {10}
     debug    string of 16 numbers each 0-3 {0}

    ... class add ... htb rate R1 [burst B1] [mpu B] [overhead O]
                          [prio P] [slot S] [pslot PS]
                          [ceil R2] [cburst B2] [mtu MTU] [quantum Q]
     rate     rate allocated to this class (class can still borrow)
     burst    max bytes burst which can be accumulated during idle period {computed}
     mpu      minimum packet size used in rate computations
     overhead per-packet size overhead used in rate computations
     linklay  adapting to a linklayer e.g. atm
     ceil     definite upper class rate (no borrows) {rate}
     cburst   burst but for ceil {computed}
     mtu      max packet size we create rate map for {1600}
     prio     priority of leaf; lower are served first {0}
根据HTB的官方文档显示，quantum是在可以“借”的情况下，一次可以“借”多少，并且说这个值最好尽量的小，但要大于MTU；而且这个
值是不用手动设置，它会根据r2q的值计算出来。
     quantum  how much bytes to serve from leaf at once {use r2q}
     */ //如果应用层设置为超过8，则默认修改为7，见htb_change_class
	int prio;		/* these two are used only by leaves... */ //取值范围小于TC_HTB_NUMPRIO      见htb_activate
	//quantum参数在htb_dequeue_tree中会使用到
	int quantum;		/* but stored for parent-to-leaf return */ // 定额参数, 缺省是取物理网卡的队列长度值  最小长度为1000 最大200000 可以通过应用层参数quantum设置

	union {
		struct htb_class_leaf { // 如果该节点是叶子节点， 则使用leaf结构, 实现具体的流控处理；
			struct Qdisc *q; //新建的htb class分类规则的默认叶子qdisc为pfifo_qdisc_ops
			int deficit[TC_HTB_MAXDEPTH];// 不同层次深度的赤字        出队的时候用到，见htb_dequeue_tree。 没发送SKB->LEN的数据包，该值减少len
			struct list_head drop_list;// 挂接到丢包链表, 添加到htb_sched->drops[]链表中，见htb_activate
		} leaf;
		// 如果非叶子节点, 使用HTB内部类别结构inner, 用于形成分类树
		struct htb_class_inner {
            // 提供数据包的红黑树结构, 是一个按类别ID进行排序的有序表, 以二叉树实现, 
            // 不同优先权对应不同的二叉树
            // feed存放其子孙是yellow的节点，子孙需要向父类借额度，才可以进行调度; 见htb_activate_prios
			struct rb_root feed[TC_HTB_NUMPRIO];	/* feed trees */  //class子类通过prio添加到父节点的feed[i]上，见htb_add_to_id_tree
			// 当前优先权树中正在处理的那个节点的指针
			struct rb_node *ptr[TC_HTB_NUMPRIO];	/* current class ptr */
			/* When class changes from state 1->2 and disconnects from
			   parent's feed then we lost ptr value and start from the
			   first child again. Here we store classid of the
			   last valid ptr (used when ptr is NULL). */
			   // 上一个有效的树节点的类别ID，见htb_deactivate_prios
			u32 last_ptr_id[TC_HTB_NUMPRIO];
		} inner;
	} un;
    // 类别结构自己的数据包供应树
	struct rb_node node[TC_HTB_NUMPRIO];	/* node for self or feed tree */
	
    // 事件树, 实际是等待树, 当带宽超过限制时会将该类别节点挂接到HTB流控节点的
    // 等待队列wait_pq
	struct rb_node pq_node;	/* node for event queue */
	psched_time_t pq_key;

    /*从这里可以看到，如果是非叶子节点，则可能是其下级class或者叶子节点的或操作，
	//所以如果是非叶子节点，第一层level最多两个优先级，第二层level最多三个优先级，第七层level最多8个优先级，见htb_activate_prios*/
    // 激活的优先权参数, 非0表示相应位数的数据队列有数据包可用  某位为1表示该位对应的un->inner->feed[i]优先权的数据可用
	int prio_activity;	/* for which prios are we active */ //赋值见htb_activate  和上面的prio一样 cl->prio_activity = 1 << cl->prio;
	enum htb_cmode cmode;	/* current mode of the class */ // 当前模式, 表示是否可发送数据包  默认HTB_CAN_SEND

	/* class attached filters *///tc filter add dev eth0 parent 1:3 protocol ip prio 100  xxxx
	//该class分类对应的过滤器  //在htb_find_tcf中如果查找不到class则直接把过滤器添加到跟过滤器上
	struct tcf_proto *filter_list; //每个分类信息中都有一个这样的过滤器，过滤器是为具体的某个类节点添加的,上面就是在1:3上面添加一个过滤器
	int filter_cnt; //见htb_bind_filter // 过滤器使用计数  

	/* token bucket parameters */
	struct qdisc_rate_table *rate;	/* rate table of the class itself */ // 令牌率  通过这个加入到qdisc_rtab_list，见qdisc_put_rtab
	struct qdisc_rate_table *ceil;	/* ceiling rate (limits borrows too) */ // 峰值率 通过这个加入到qdisc_rtab_list，见qdisc_put_rtab
    //对应tc_htb_opt中的buffer和cbuffer
	long buffer, cbuffer;	/* token bucket depth/rate */ // 缓冲区/峰值缓冲区 这两个是htb令牌桶算法中的用处是:如果来了一个skb，该skb比令牌数大，则把skb数据缓存到buffer中，等令牌够的时候把skb发送出去
	psched_tdiff_t mbuffer;	/* max wait time */ // 最大等待时间  默认60 * PSCHED_TICKS_PER_SEC;
	long tokens, ctokens;	/* current number of tokens */// 当前令牌数/峰值令牌  对应tc_htb_opt中的buffer和cbuffer
	psched_time_t t_c;	/* checkpoint time */// 检查点时间
};

struct htb_sched { 
    //tc qdisc add class xxxx htb的时候创建的struct htb_class都添加到该hash表中(通过htb_class ->Qdisc_class_common ->hnode加到这里面，
    //见htb_change_class -> qdisc_class_hash_insert) ，htb_class和htb_sched关联起来，
    //clhash初始化地方在qdisc_class_hash_init
    ////创建htb_class的时候创建的struct htb_class是加入到htb_sched(htb qdisc的私有数据)->clhash中，但并没有形成一颗红黑树，形成红黑树是在htb_enqueue->htb_activate实现
    struct Qdisc_class_hash clhash; //tc class add parent 2 classid 2:3 xx ,根据classid 2:3加入到该链表中，这里面存储的就是简单的classid号以及该链表上tc add class有多少个class

    //cl->un.leaf.drop_list是加到该表中的，见htb_activate , htb_class->un.leaf.drop_list添加到对应的drops[]中
	struct list_head drops[TC_HTB_NUMPRIO];/* active leaves (for drops) */ //和class->prio有关系，见htb_activate

	/* self list - roots of self generating tree */
	// RB树根节点, 对应每一层的每一个优先权值都有一个RB树， 见htb_add_class_to_row
	struct rb_root row[TC_HTB_MAXDEPTH][TC_HTB_NUMPRIO]; //row存放green节点，就是token额度还有剩余、可以进行调度的class节点； 
	int row_mask[TC_HTB_MAXDEPTH];// 掩码, 表示该层的哪些优先权值的树有效。见htb_add_class_to_row

    /* ptr是DRR算法的一个标记，指向当前可以进行调度的节点（类）。 如果当前节点的deficit用完了，htb_next_rb_node()会将ptr指针指向当前节点
    的下一个节点，然后再从ptr指向的节点进行调度。*/
	struct rb_node *ptr[TC_HTB_MAXDEPTH][TC_HTB_NUMPRIO];// 父节点指针
	u32 last_ptr_id[TC_HTB_MAXDEPTH][TC_HTB_NUMPRIO];// 上次使用的非空父节点的类别ID

	/* self wait list - roots of wait PQs per row */
	//wait_pq存放yellow和red节点，在特定时间进行检查是否可以把节点恢复到green。   
	struct rb_root wait_pq[TC_HTB_MAXDEPTH];// 等待队列, 用来挂接那些带宽超出限制的节点

	/* time of nearest event per level (row) */
	psched_time_t near_ev_cache[TC_HTB_MAXDEPTH];

    //tc qdisc del add eth0 root handle 22 htb default 3333333  // 缺省类别 minor id of class to which unclassified packets are sent {0}
	int defcls;		/* class where unclassified flows go to */ //无法通过过滤器选择子类的SKB默认走该分类，

	/* filters for qdisc itself */
	struct tcf_proto *filter_list;//在htb_find_tcf中如果查找不到class则直接把过滤器添加到跟过滤器上

    //DRR quantums are computed as rate in Bps/r2q {10}   应用层设置的默认值为10，见htb_parse_opt
	int rate2quantum;	/* quant = rate / rate2quantum */  // 速率到定额转换参数  初始值为1，见htb_init
	psched_time_t now;	/* cached dequeue time */ // 当前时间
	struct qdisc_watchdog watchdog;

	/* non shaped skbs; let them go directly thru */
	//如果SKB到来的时候没有匹配的过滤器，并且默认default队列规程也没匹配成功，则直接使用私有信息中的direct_queue队列入队，见htb_enqueue
	struct sk_buff_head direct_queue; //能否入队就是用该队列上的SKB个数与下面的direct_qlen做比较,  这个skb链表上面的东西是不需要限速的，见htb_dequeue
	int direct_qlen;	/* max qlen of above */ //q->direct_qlen = qdisc_dev(sch)->tx_queue_len;

	long direct_pkts;// 直接处理的数据包计数

#define HTB_WARN_TOOMANYEVENTS	0x1
	unsigned int warned;	/* only one warning */
	struct work_struct work;
};

/* find class in global hash table using given handle */// 根据类别ID查找类别结构 // 根据句柄handle查找HTB节点
static inline struct htb_class *htb_find(u32 handle, struct Qdisc *sch)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, handle);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct htb_class, common);
}

/**
 * htb_classify - classify a packet into class
 *
 * It returns NULL if the packet should be dropped or -1 if the packet
 * should be passed directly thru. In all other cases leaf class is returned.
 * We allow direct class selection by classid in priority. The we examine
 * filters in qdisc and in inner nodes (if higher filter points to the inner
 * node). If we end up with classid MAJOR:0 we enqueue the skb into special
 * internal fifo (direct). These packets then go directly thru. If we still
 * have no valid leaf we try to use MAJOR:default leaf. It still unsuccessfull
 * then finish and return direct queue.
 */ 
    // HTB分类操作, 对数据包进行分类, 然后根据类别进行相关操作
    // 返回NULL表示没找到, 返回-1表示是直接通过(不分类)的数据包
//该SKB没有对应匹配的过滤器，则使用默认的过滤器，也就是tc qdisc add xxxxx htb default a中的a。见htb_classify
#define HTB_DIRECT (struct htb_class*)-1 
static struct htb_class *htb_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

	/* allow to select class by setting skb->priority to valid classid;
	   note that nfmark can be used too by attaching filter fw with no
	   rules in it */
	if (skb->priority == sch->handle)// 如果数据包优先权值就等于流控节点和句柄handle, 属于根节点操作, 直接处理
		return HTB_DIRECT;	/* X:0 (direct flow) selected */
	if ((cl = htb_find(skb->priority, sch)) != NULL && cl->level == 0)// 查找和数据包优先权值对应的HTB叶子节点, 找到则返回
		return cl;

    /*
    // 以下处理是没有找到和skb->priority直接对应的HTB叶子节点, 应该说实际应用中大部分都是skb->priority为0的, 所以一般都会运行到这里
    */
	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	tcf = q->filter_list;//过滤器链表
	//通过skb内容来匹配tc filter链表tp，找到返回对应的分类节点，匹配成功返回0并把匹配的过滤器所在的tc class分类节点信息存到res中，匹配成功返回0
	while (tcf && (result = tc_classify(skb, tcf, &res)) >= 0) {
#ifdef CONFIG_NET_CLS_ACT // 定义了可对分类结果进行动作的内核选项的情况
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			return NULL;
		}
#endif
		if ((cl = (void *)res.class) == NULL) { //如果返回的结果中的res.class=0
			if (res.classid == sch->handle)// 如果分类结果的ID等于流控句柄, 直接处理
				return HTB_DIRECT;	/* X:0 (direct flow) */
			if ((cl = htb_find(res.classid, sch)) == NULL)
				break;	/* filter selected invalid classid */
		}
		if (!cl->level)
			return cl;	/* we hit leaf; return it */

		/* we have got inner class; apply inner filter chain */
		tcf = cl->filter_list;
	}
	// 循环外是没找到分类的情况
	/* classification failed; try to use default class */// 用缺省类别ID查找, 看是否定义了缺省类别
	cl = htb_find(TC_H_MAKE(TC_H_MAJ(sch->handle), q->defcls), sch);
	if (!cl || cl->level) //该SKB没有对应匹配的过滤器，则使用默认的过滤器查找，也就是tc qdisc add xxxxx htb default a中的a。如果默认的分类也没找到，则返回HTB_DIRECT
		return HTB_DIRECT;	/* bad default .. this is safe bet */
	return cl;
}

/**
 * htb_add_to_id_tree - adds class to the round robin list
 *
 * Routine adds class to the list (actually tree) sorted by classid.
 * Make sure that class is not already on such list for given prio.
 */ //把class  cl添加到红黑树中
static void htb_add_to_id_tree(struct rb_root *root,
			       struct htb_class *cl, int prio)
{
	struct rb_node **p = &root->rb_node, *parent = NULL;
    
    // RB树是有序表, 根据类别ID排序, 值大的到右节点, 小的到左节点
    // 循环, 查找树中合适的位置插入类别节点cl
	while (*p) {//先要找到插入那个rh数节点后面
		struct htb_class *c;
		parent = *p;
		c = rb_entry(parent, struct htb_class, node[prio]);

		if (cl->common.classid > c->common.classid)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}

	// 进行RB树的插入操作, RB树标准函数操作
	rb_link_node(&cl->node[prio], parent, p);
	rb_insert_color(&cl->node[prio], root);
}

/**
 * htb_add_to_wait_tree - adds class to the event queue with delay
 *
 * The class is added to priority event queue to indicate that class will
 * change its mode in cl->pq_key microseconds. Make sure that class is not
 * already in the queue.
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/
static void htb_add_to_wait_tree(struct htb_sched *q,
				 struct htb_class *cl, long delay)
{
	struct rb_node **p = &q->wait_pq[cl->level].rb_node, *parent = NULL;

	cl->pq_key = q->now + delay;
	if (cl->pq_key == q->now)
		cl->pq_key++;

	/* update the nearest event cache */
	if (q->near_ev_cache[cl->level] > cl->pq_key)
		q->near_ev_cache[cl->level] = cl->pq_key;

	while (*p) {
		struct htb_class *c;
		parent = *p;
		c = rb_entry(parent, struct htb_class, pq_node);
		if (cl->pq_key >= c->pq_key)
			p = &parent->rb_right;
		else
			p = &parent->rb_left;
	}
	rb_link_node(&cl->pq_node, parent, p);
	rb_insert_color(&cl->pq_node, &q->wait_pq[cl->level]);
}

/**
 * htb_next_rb_node - finds next node in binary tree
 *
 * When we are past last key we return NULL.
 * Average complexity is 2 steps per call.
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/ //该函数执行后，n会执行该红黑树的下一个节点
static inline void htb_next_rb_node(struct rb_node **n)
{
	*n = rb_next(*n);
}

/**
 * htb_add_class_to_row - add class to its row
 *
 * The class is added to row at priorities marked in mask.
 * It does nothing if mask == 0.
 */ 
//把cl添加到q->row[cl->level] + prio(cl->level层，prio优先级)的红黑树跟中。
// RB树根节点, 对应每一层的每一个优先权值都有一个RB树。 也就是根据cl->level和mask中的prio来确定把cl添加到htb_sched私有数据部分的那个跟row[][]中
static inline void htb_add_class_to_row(struct htb_sched *q,
					struct htb_class *cl, int mask)
{
    // 将cl层次对应的ROW的row_mask或上新的mask, 表示有对应prio的数据了
	q->row_mask[cl->level] |= mask;
	while (mask) {
		int prio = ffz(~mask);
		mask &= ~(1 << prio);//获取mask中每位为1的位，例如0X23,则while循环的prio依次是0 1 5几个数字
		htb_add_to_id_tree(q->row[cl->level] + prio, cl, prio);//q->row[cl->level] + prio对应cl->level层的prio优先级红黑树根
	}
}

/* If this triggers, it is a bug in this code, but it need not be fatal */
/*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/
static void htb_safe_rb_erase(struct rb_node *rb, struct rb_root *root)
{
	if (RB_EMPTY_NODE(rb)) {
		WARN_ON(1);
	} else {
		rb_erase(rb, root);
		RB_CLEAR_NODE(rb);
	}
}


/**
 * htb_remove_class_from_row - removes class from its row
 *
 * The class is removed from row at priorities marked in mask.
 * It does nothing if mask == 0.
 */
static inline void htb_remove_class_from_row(struct htb_sched *q,
						 struct htb_class *cl, int mask)
{
	int m = 0;

	while (mask) {
		int prio = ffz(~mask);// prio为mask第一个1位的位置

		mask &= ~(1 << prio);// 去掉该位

		// 如果流控节点的该层该prio的rb树节点指向的是cl的prio的rb树节点, 更新到树的下一个rb节点
		if (q->ptr[cl->level][prio] == cl->node + prio)
			htb_next_rb_node(q->ptr[cl->level] + prio);

		htb_safe_rb_erase(cl->node + prio, q->row[cl->level] + prio);// 从ROW树中断开cl
		if (!q->row[cl->level][prio].rb_node)// 如果该层该prio的rb树位空, 记录其位置
			m |= 1 << prio;
	}
	q->row_mask[cl->level] &= ~m;// 在ROW掩码中将与rb树为空的那些prio位清空
}

/**
 * htb_activate_prios - creates active classe's feed chain
 *
 * The class is connected to ancestors and/or appropriate rows
 * for priorities it is participating on. cl->cmode must be new
 * (activated) mode. It does nothing if cl->prio_activity == 0.
 */
// 激活操作, 建立数据提供树
// cl->prio_activity为0时就是一个空函数, 不过从前面看prio_activity似乎是不会为0的
//该函数就是把cl添加到p->un.inner.feed[prio]上，同时跟新父p->prio_activity中的prio位置1，同时父的父上对应的p->prio_activity中的prio位置1，
//也就是整棵树从该cl以上都可用。 参考http://luxik.cdi.cz/~devik/qos/htb/manual/theory.htm        http://blog.chinaunix.net/uid-7220314-id-208698.html 
static void htb_activate_prios(struct htb_sched *q, struct htb_class *cl)
{
	struct htb_class *p = cl->parent;
	long m, mask = cl->prio_activity;// prio_activity是作为一个掩码, 可应该只有一位为1

    // 在当前模式是HTB_MAY_BORROW情况下进入循环, 某些情况下这些类别是可以激活的
    // 绝大多数情况p和mask的初始值应该都是非0值
	while (cl->cmode == HTB_MAY_BORROW && p && mask) {  //图解参考<Hierachical token bucket theory>  http://luxik.cdi.cz/~devik/qos/htb/manual/theory.htm
		m = mask;// 备份mask值
		while (m) {
            // 掩码取反, 找第一个0位的位置, 也就是原来最低为1的位的位置
            // prio越小, 等级越高, 取数据包也是先从prio值小的节点取
			int prio = ffz(~m); //通过while(m)可以知道，prio就是mask中每位为1所在的位置
			m &= ~(1 << prio);// 清除该位   最后得到的结果就是m的值为mask的最低位1变0后的值
     
            // p是父节点, 所以inner结构肯定有效, 不会使用leaf结构的
            // 如果父节点的prio优先权的数据包的提供树已经存在, 在掩码中去掉该位
			if (p->un.inner.feed[prio].rb_node)
				/* parent already has its feed in use so that
				   reset bit in mask as parent is already ok */
				mask &= ~(1 << prio);                           

            // 将该类别加到父节点的prio优先权提供数据包的节点树中
			htb_add_to_id_tree(p->un.inner.feed + prio, cl, prio);
		}
		
        // 父节点的prio_activity或上mask中的置1位, 某位为1表示该位对应的优先权的数据可用
        //从这里可以看到，如果是非叶子节点，则可能是其下级class或者叶子节点的或操作，
		//所以如果是非叶子节点，第一层level最多两个优先级，第二层level最多三个优先级，第七层level最多8个优先级
		p->prio_activity |= mask; 
		// 循环到上一层, 当前类别更新父节点, 父节点更新为祖父节点
		cl = p;
		p = cl->parent;
	}
	
    // 如果cl是HTB_CAN_SEND模式, 将该类别添加到合适的ROW中
    // 此时的cl可能已经不是原来的cl了,而是原cl的长辈节点了
	if (cl->cmode == HTB_CAN_SEND && mask)
		htb_add_class_to_row(q, cl, mask);
}

/**
 * htb_deactivate_prios - remove class from feed chain
 *
 * cl->cmode must represent old mode (before deactivation). It does
 * nothing if cl->prio_activity == 0. Class is removed from all feed
 * chains and rows.
 */
static void htb_deactivate_prios(struct htb_sched *q, struct htb_class *cl)
{
	struct htb_class *p = cl->parent;
	long m, mask = cl->prio_activity; // 类别结构的优先权活性值作为掩码, 如果是0的话本函数相当于空函数

    
    // 在当前模式是HTB_MAY_BORROW情况下进入循环, 
    // 绝大多数情况p和mask的初始值应该都是非0值
	while (cl->cmode == HTB_MAY_BORROW && p && mask) {
		m = mask;// 备份掩码
		mask = 0;// 掩码清零
		while (m) {
			int prio = ffz(~m);// prio为m的第一个1值的位(取反后第一个0值的位)
			m &= ~(1 << prio);// 去除该位

			if (p->un.inner.ptr[prio] == cl->node + prio) {// 如果该类别prio对应的rb树是父节点中正在处理的
				/* we are removing child which is pointed to from
				   parent feed - forget the pointer but remember
				   classid */
				p->un.inner.last_ptr_id[prio] = cl->common.classid;// 将cl的类别ID保存到last_ptr_id中prio对应位置
				p->un.inner.ptr[prio] = NULL;
			}

			htb_safe_rb_erase(cl->node + prio, p->un.inner.feed + prio);// 类别节点从与prio相应rb树中断开

			if(!p->un.inner.feed[prio].rb_node)//对已经空了的rb树保存其位置
				mask |= 1 << prio;
		}

		p->prio_activity &= ~mask;// 将已经空了的rb数掩码从父节点的活性值掩码中去掉
		cl = p;// 转到上一层处理
		p = cl->parent;

	}
	if (cl->cmode == HTB_CAN_SEND && mask)// 如果当前类别cl的模式是可以发送(无阻塞, 无借带宽), 将cl从ROW的相关树中断开
		htb_remove_class_from_row(q, cl, mask);
}

static inline long htb_lowater(const struct htb_class *cl)
{
	if (htb_hysteresis)
		return cl->cmode != HTB_CANT_SEND ? -cl->cbuffer : 0;
	else
		return 0;
}
static inline long htb_hiwater(const struct htb_class *cl)
{
	if (htb_hysteresis)
		return cl->cmode == HTB_CAN_SEND ? -cl->buffer : 0;
	else
		return 0;
}


/**
 * htb_class_mode - computes and returns current class mode
 *
 * It computes cl's mode at time cl->t_c+diff and returns it. If mode
 * is not HTB_CAN_SEND then cl->pq_key is updated to time difference
 * from now to time when cl will change its state.
 * Also it is worth to note that class mode doesn't change simply
 * at cl->{c,}tokens == 0 but there can rather be hysteresis of
 * 0 .. -cl->{c,}buffer range. It is meant to limit number of
 * mode transitions per time unit. The speed gain is about 1/6.
 */
static inline enum htb_cmode
htb_class_mode(struct htb_class *cl, long *diff)
{
	long toks;

	if ((toks = (cl->ctokens + *diff)) < htb_lowater(cl)) {// 计算类别的Ceil令牌
		*diff = -toks;// 如果令牌小于低限 
		return HTB_CANT_SEND;
	}

    
    // 计算类别的普通令牌
    // 如果令牌大于高限, 模式为可发送
	if ((toks = (cl->tokens + *diff)) >= htb_hiwater(cl))
		return HTB_CAN_SEND;

	*diff = -toks;
	return HTB_MAY_BORROW;// 否则模式为可借
}

/**
 * htb_change_class_mode - changes classe's mode
 *
 * This should be the only way how to change classe's mode under normal
 * cirsumstances. Routine will update feed lists linkage, change mode
 * and add class to the wait event queue if appropriate. New mode should
 * be different from old one and cl->pq_key has to be valid if changing
 * to mode other than HTB_CAN_SEND (see htb_add_to_wait_tree).
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/ // 调整类别节点的发送模式
static void
htb_change_class_mode(struct htb_sched *q, struct htb_class *cl, long *diff) //调整class模式，同时通过htb_activate_prios重新形成row leaf树等
{
	enum htb_cmode new_mode = htb_class_mode(cl, diff);// 根据变化值计算新模式

	if (new_mode == cl->cmode)// 模式没变, 返回
		return;

	if (cl->prio_activity) {	/* not necessary: speed optimization */// cl->prio_activity非0表示是活动的节点, 需要停止后再更新模式
		if (cl->cmode != HTB_CANT_SEND)// 如原来的模式不可发送数据, 先停该节点
			htb_deactivate_prios(q, cl);
		cl->cmode = new_mode;
		if (new_mode != HTB_CANT_SEND)// 如果新模式不是禁止发送, 重新激活节点
			htb_activate_prios(q, cl);
	} else // 非活动类别节点, 直接更新模式值
		cl->cmode = new_mode;
}

/**
 * htb_activate - inserts leaf cl into appropriate active feeds
 *
 * Routine learns (new) priority of leaf and activates feed chain
 * for the prio. It can be called on already active leaf safely.
 * It also adds leaf into droplist.
 */
// 激活类别结构, 将该类别节点作为数据包提供者, 而数据类别表提供是一个
// 有序表, 以RB树形式实现
//创建htb_class的时候创建的struct htb_class是加入到htb_sched(htb qdisc的私有数据)->clhash中，但并没有形成一颗红黑树，形成红黑树是在htb_enqueue->htb_activate实现
static inline void htb_activate(struct htb_sched *q, struct htb_class *cl)
{
	WARN_ON(cl->level || !cl->un.leaf.q || !cl->un.leaf.q->q.qlen);

	if (!cl->prio_activity) {// 如果类别的prio_activity参数为0才进行操作, 非0表示已经激活了	    
        // prio_activity是通过叶子节点的prio值来设置的, 至少是1, 最大是1<<7, 非0值
        // leaf.aprio保存当前的leaf.prio
		cl->prio_activity = 1 << cl->prio;
		htb_activate_prios(q, cl);// 进行实际的激活操作
		list_add_tail(&cl->un.leaf.drop_list,
			      q->drops + cl->prio);// 根据leaf.aprio添加到指定的优先权位置的丢包链表
	}
}

/**
 * htb_deactivate - remove leaf cl from active feeds
 *
 * Make sure that leaf is active. In the other words it can't be called
 * with non-active leaf. It also removes class from the drop list.
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/
//将类别叶子节点从活动的数据包提供树中去掉,cl是叶子节点
static inline void htb_deactivate(struct htb_sched *q, struct htb_class *cl)
{
	WARN_ON(!cl->prio_activity);

	htb_deactivate_prios(q, cl);// 关闭
	cl->prio_activity = 0;// 类别的活性值prio_activity清零
	list_del_init(&cl->un.leaf.drop_list);
}

static int htb_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	int uninitialized_var(ret);
	struct htb_sched *q = qdisc_priv(sch);

	//这里通过过滤器如果匹配的class为叶子无聊队列规程，则可以跳过中间队列规程树，直接跳到叶子，直接入队。参考<HTB介绍以及使用.doc>
	struct htb_class *cl = htb_classify(skb, sch, &ret);//进队首先调用的是分类器，查看数据包要放到那个队列中，然后再进行进队操作

	if (cl == HTB_DIRECT) { //在过滤器中没有找到匹配的分类，并且默认的class也没找到，也就是tc adisc add xxxxx defualt 5中的5。则直接使用htb_sched->direct_queue入队
		/* enqueue to helper queue */
		if (q->direct_queue.qlen < q->direct_qlen) {
			__skb_queue_tail(&q->direct_queue, skb);
			q->direct_pkts++;
		} else {
			kfree_skb(skb);
			sch->qstats.drops++;
			return NET_XMIT_DROP;
		}
#ifdef CONFIG_NET_CLS_ACT
	} else if (!cl) {
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
#endif
	} else { //如果SKB是满足过滤器对应的分类规则，或者默认default中的队列规程存在，则走这里
	    if ((ret = qdisc_enqueue(skb, cl->un.leaf.q)) != NET_XMIT_SUCCESS) { //递归循环入队，直到找到叶子节点,htb默认的是pfifo_qdisc_ops
    		if (net_xmit_drop_count(ret)) { //入队失败
    			sch->qstats.drops++;
    			cl->qstats.drops++;
    		}
    		return ret;
    	} else { //入队成功，入队实际上是加到叶子无类队列规程上面，例如pfifo fifo_fast等
    		cl->bstats.packets +=
    			skb_is_gso(skb)?skb_shinfo(skb)->gso_segs:1;

    		/*
                // 激活HTB类别, 建立该类别的数据提供树, 这样dequeue时可以从中取数据包
                // 只有类别节点的模式是可发送和可租借的情况下才会激活, 如果节点是阻塞
                // 模式, 则不会被激活
    		    */
    		cl->bstats.bytes += qdisc_pkt_len(skb);
    		htb_activate(q, cl);
    	}
	}

	sch->q.qlen++;
	sch->bstats.packets += skb_is_gso(skb)?skb_shinfo(skb)->gso_segs:1;
	sch->bstats.bytes += qdisc_pkt_len(skb);
	return NET_XMIT_SUCCESS;
}

static inline void htb_accnt_tokens(struct htb_class *cl, int bytes, long diff)
{
	long toks = diff + cl->tokens;

	if (toks > cl->buffer)
		toks = cl->buffer;
	toks -= (long) qdisc_l2t(cl->rate, bytes);
	if (toks <= -cl->mbuffer)
		toks = 1 - cl->mbuffer;

	cl->tokens = toks;
}

static inline void htb_accnt_ctokens(struct htb_class *cl, int bytes, long diff)
{
	long toks = diff + cl->ctokens;

	if (toks > cl->cbuffer)
		toks = cl->cbuffer;
		
	toks -= (long) qdisc_l2t(cl->ceil, bytes);
	if (toks <= -cl->mbuffer)
		toks = 1 - cl->mbuffer;

	cl->ctokens = toks;
}

/**
 * htb_charge_class - charges amount "bytes" to leaf and ancestors
 *
 * Routine assumes that packet "bytes" long was dequeued from leaf cl
 * borrowing from "level". It accounts bytes to ceil leaky bucket for
 * leaf and all ancestors and to rate bucket for ancestors at levels
 * "level" and higher. It also handles possible change of mode resulting
 * from the update. Note that mode can also increase here (MAY_BORROW to
 * CAN_SEND) because we can use more precise clock that event queue here.
 * In such case we remove class from event queue first.
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/// 处理该流控节点cl以及其所有父节点q的令牌情况, 调整该类别的模式cmode         //调整class模式，同时通过htb_activate_prios重新形成row leaf树等
static void htb_charge_class(struct htb_sched *q, struct htb_class *cl,
			     int level, struct sk_buff *skb)
{
	int bytes = qdisc_pkt_len(skb);
	enum htb_cmode old_mode;
	long diff;

    // 循环向上到根节点
	while (cl) {
	    // 时间间隔
		diff = psched_tdiff_bounded(q->now, cl->t_c, cl->mbuffer);
		
        // 类别层次高的借出增加
		if (cl->level >= level) {
			if (cl->level == level)
				cl->xstats.lends++;

			//计算普通令牌
			htb_accnt_tokens(cl, bytes, diff);
		} else {
            // 类别层次低
            // 借入增加
			cl->xstats.borrows++;
			cl->tokens += diff;	/* we moved t_c; update tokens */// 令牌增加
		}
		htb_accnt_ctokens(cl, bytes, diff);// 计算Ceil令牌
		cl->t_c = q->now;

		old_mode = cl->cmode;// 保存类别节点原来的模式
		diff = 0;
		
        // 根据新的令牌,缓冲区数来更新类别节点的模式, 因为前面diff数据已经在令牌中修改过了
        // 所以现在diff输入值设为0了, 函数结束, 类别模式不是可发送时, diff中保存当前令牌数
        // 的负值
		htb_change_class_mode(q, cl, &diff);//调整class模式，同时通过htb_activate_prios重新形成row leaf树等
		if (old_mode != cl->cmode) { // 如果类别模式发生了变化。 
			if (old_mode != HTB_CAN_SEND)// 如果老模式不是可以直接发送的模式(HTB_CAN_SEND), 说明在等待RB树中, 要从该RB树中删除
				htb_safe_rb_erase(&cl->pq_node, q->wait_pq + cl->level);
			if (cl->cmode != HTB_CAN_SEND)
				htb_add_to_wait_tree(q, cl, diff);// 如果当前新模式不是可以直接发送的模式(HTB_CAN_SEND), 挂接到合适的等待RB树
		}

		/* update byte stats except for leaves which are already updated */
		if (cl->level) {// 如果是中间节点, 更新其统计值, 因为对于叶子节点已经在数据包出队时处理过了
			cl->bstats.bytes += bytes;
			cl->bstats.packets += skb_is_gso(skb)?
					skb_shinfo(skb)->gso_segs:1;
		}
		cl = cl->parent;
	}
}

/**
 * htb_do_events - make mode changes to classes at the level
 *
 * Scans event queue for pending events and applies them. Returns time of
 * next pending event (0 for no event in pq, q->now for too many events).
 * Note: Applied are events whose have cl->pq_key <= q->now.
 */
/*
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by
*/ // 对第level号等待树的类别节点进行模式调整
static psched_time_t htb_do_events(struct htb_sched *q, int level,
				   unsigned long start)
{
	/* don't run for longer than 2 jiffies; 2 is used instead of
	   1 to simplify things when jiffy is going to be incremented
	   too soon */
	unsigned long stop_at = start + 2;
	while (time_before(jiffies, stop_at)) {
		struct htb_class *cl;
		long diff;
		struct rb_node *p = rb_first(&q->wait_pq[level]);

		if (!p)
			return 0;

		cl = rb_entry(p, struct htb_class, pq_node);
		if (cl->pq_key > q->now)
			return cl->pq_key;

		htb_safe_rb_erase(p, q->wait_pq + level);
		diff = psched_tdiff_bounded(q->now, cl->t_c, cl->mbuffer);
		htb_change_class_mode(q, cl, &diff);
		if (cl->cmode != HTB_CAN_SEND)
			htb_add_to_wait_tree(q, cl, diff);
	}

	/* too much load - let's continue after a break for scheduling */
	if (!(q->warned & HTB_WARN_TOOMANYEVENTS)) {
		printk(KERN_WARNING "htb: too many events!\n");
		q->warned |= HTB_WARN_TOOMANYEVENTS;
	}

	return q->now;
}

/* Returns class->node+prio from id-tree where classe's id is >= id. NULL
   is no such one exists. */
static struct rb_node *htb_id_find_next_upper(int prio, struct rb_node *n,
					      u32 id)
{
	struct rb_node *r = NULL;
	while (n) {
		struct htb_class *cl =
		    rb_entry(n, struct htb_class, node[prio]);

		if (id > cl->common.classid) {
			n = n->rb_right;
		} else if (id < cl->common.classid) {
			r = n;
			n = n->rb_left;
		} else {
			return n;
		}
	}
	return r;
}

/**
 * htb_lookup_leaf - returns next leaf class in DRR order
 *
 * Find leaf where current feed pointers points to.
 *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by
*/ // 查找叶子分类节点  pptr存储最后找到的叶子节点的父class，   图形化理解参考<Linux htb 源代码分析 >
static struct htb_class *htb_lookup_leaf(struct rb_root *tree, int prio,
					 struct rb_node **pptr, u32 * pid)
{
	int i;
	struct {
		struct rb_node *root;// 根节点
		struct rb_node **pptr;// 父节点地址
		u32 *pid;
	} stk[TC_HTB_MAXDEPTH], *sp = stk; //定义了8个元素的数组，初始sp指向第0个元素。 

	BUG_ON(!tree->rb_node);
	sp->root = tree->rb_node;
	sp->pptr = pptr;
	sp->pid = pid;

	for (i = 0; i < 65535; i++) {// 64K次的循环, 为什么是64K呢
		if (!*sp->pptr && *sp->pid) {// 父节点为空, 可父ID非0, 重新查找父节点
			/* ptr was invalidated but id is valid - try to recover
			   the original or next ptr */
			*sp->pptr =
			    htb_id_find_next_upper(prio, sp->root, *sp->pid);
		}

		// 父ID清零
		*sp->pid = 0;	/* ptr is valid now so that remove this hint as it
				   can become out of date quickly */
		if (!*sp->pptr) {	/* we are at right end; rewind & go up */ // 如果父节点还是为空
			*sp->pptr = sp->root;// 父节点设置为根节点
			while ((*sp->pptr)->rb_left)
				*sp->pptr = (*sp->pptr)->rb_left;// 父节点设置为最下层的左叶子节点

			// 如果不再是数组的0元素, 这是下面代码执行过的情况
			if (sp > stk) {
				sp--;// 移到前一元素
				if (!*sp->pptr) {// 如果该元素的父节点为空, 返回空, 这里是循环出口1
					WARN_ON(1);
					return NULL;
				}
				htb_next_rb_node(sp->pptr);// pptr更新为下一个节点
			}
		} else {
			struct htb_class *cl;
			// 提取父节点中的第prio号节点对应的HTB类别结构
			cl = rb_entry(*sp->pptr, struct htb_class, node[prio]);
			if (!cl->level)// 如果是叶子节点, 返回, 这里是循环出口2
				return cl;
			
            // 移动到stk数组的下一项
            // 用该HTB类别结构参数来初始化该数组项的参数重新循环
			(++sp)->root = cl->un.inner.feed[prio].rb_node;
			sp->pptr = cl->un.inner.ptr + prio;
			sp->pid = cl->un.inner.last_ptr_id + prio;
		}
	}
	WARN_ON(1);
	// 循环结束也没找到合适节点, 返回空
	return NULL;
}

/* dequeues packet at given priority and level; call only if
   you are sure that there is active class at prio/level 
   3.DRR是怎么实现的？ 
   
   所谓deficit round robin，是在htb_dequeue_tree()函数的末尾实现的。 
   
   860 if (likely(skb != NULL)) { 
   861      bstats_update(&cl->bstats, skb); 
   862      cl->un.leaf.deficit[level] -= qdisc_pkt_len(skb); 
   863      if (cl->un.leaf.deficit[level] < 0) { 
   864           cl->un.leaf.deficit[level] += cl->quantum; 
   865           htb_next_rb_node(level ? &cl->parent->un.inner.clprio[prio].ptr : 
   866                                              &q->hlevel[0].hprio[prio].ptr);   
   867      }  
   874 } 
   差额轮循调度；亏空轮循；差额轮询
   *//*
HTB出队过程
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue
htb_dequeue
  -> __skb_dequeue
  -> htb_do_events
    -> htb_safe_rb_erase
    -> htb_change_class_mode
    -> htb_add_to_wait_tree
  -> htb_dequeue_tree
    -> htb_lookup_leaf
    -> htb_deactivate
    -> q->dequeue
    -> htb_next_rb_node
    -> htb_charge_class
      -> htb_change_class_mode
      -> htb_safe_rb_erase
      -> htb_add_to_wait_tree
  -> htb_delay_by

*/
// 从指定的层次和优先权的RB树节点中取数据包
static struct sk_buff *htb_dequeue_tree(struct htb_sched *q, int prio,
					int level)
{
	struct sk_buff *skb = NULL;
	struct htb_class *cl, *start;
	/* look initial class up in the row */
	start = cl = htb_lookup_leaf(q->row[level] + prio, prio,
				     q->ptr[level] + prio,
				     q->last_ptr_id[level] + prio); // 根据层次和优先权值查找起始类别节点

	do {
next:
		if (unlikely(!cl))// 如果类别为空, 返回数据包为空
			return NULL;

		/* class can be empty - it is unlikely but can be true if leaf
		   qdisc drops packets in enqueue routine or if someone used
		   graft operation on the leaf since last dequeue;
		   simply deactivate and skip such class */
		if (unlikely(cl->un.leaf.q->q.qlen == 0)) {// 如果队列长度为0, 队列空的情况, 可能性较小
			struct htb_class *next;
			htb_deactivate(q, cl);// 该类别队列中没数据包了, 停止该类别结构

			/* row/level might become empty */
			if ((q->row_mask[level] & (1 << prio)) == 0)// 掩码该位为0， 表示该层该prio的rb树为空, 没有数据提供树， 返回数据包为空
				return NULL;

			next = htb_lookup_leaf(q->row[level] + prio,
					       prio, q->ptr[level] + prio,
					       q->last_ptr_id[level] + prio);// 否则重新查找该层该优先权的RB树，也就是查找q->row[level] + prio红黑树中的下一个class

            //从新找到的这个类别结构cl开始循环, 找队列非空的节点
			if (cl == start)	/* fix start if we just deleted it */
				start = next;
			cl = next;
			goto next; // 这个goto形成了大循环中的小循环, 找队列长度非空的类别节点
		}
        
        // 以下是队列长度非空的情况, 运行该类别结构的内部流控节点的出队操作, 
        // 这主要看该节点使用那种流控算法了, 如tbf之类就可以实现流量限制 
		skb = cl->un.leaf.q->dequeue(cl->un.leaf.q);
		// 取得数据包, 中断循环准备返回
		if (likely(skb != NULL))
			break;

		qdisc_warn_nonwc("htb", cl->un.leaf.q);// 没取得数据包, 打印警告信息, 该信息在循环中只打印一次
		htb_next_rb_node((level ? cl->parent->un.inner.ptr : q->ptr[0]) + prio);// 更新到下一个rb树节点
		cl = htb_lookup_leaf(q->row[level] + prio, prio,
				     q->ptr[level] + prio,
				     q->last_ptr_id[level] + prio);// 继续查找该层该优先权的RB树中找叶子类别节点, 循环
    
    // 当找到的新节点不是起始节点就进行循环直到取得数据包, 当遍历完后会又回到start节点
    // 而中断循环
	} while (cl != start);

	if (likely(skb != NULL)) {    
        // 找到数据包的情况, 可能性很大
        // 计算赤字deficit, 减数据包长度, 而deficit是初始化为0的
		cl->un.leaf.deficit[level] -= qdisc_pkt_len(skb);
		// 如果该类别节点的赤字为负, 增加一个定额量, 缺省是物理网卡的队列长度
		if (cl->un.leaf.deficit[level] < 0) {
			cl->un.leaf.deficit[level] += cl->quantum;
            // 更新到下一个rb树节点, 如果是中间节点, 则更新父节点的内部结构中的指针, 否则
            // 从流控结构中更新, 实现同一类别树中不同类别类别节点的转换, 不会一直限制在一个节点
            //该函数调用后会让cl->parent->un.inner.ptr + prio或者q->ptr[0]  + prio指向下一个节点
			htb_next_rb_node((level ? cl->parent->un.inner.ptr : q->ptr[0]) + prio);
		}
		// 如果赤字为正就不会进行RB数节点的更换
		/* this used to be after charge_class but this constelation
		   gives us slightly better performance */
		// 如果队列空了, 停止该类别
		if (!cl->un.leaf.q->q.qlen)
			htb_deactivate(q, cl);
		// 处理该流控节点以及其所有父节点的令牌情况, 调整该类别的模式cmode
		htb_charge_class(q, cl, level, skb);
	}
	return skb;
}

/*
HTB的出队是个非常复杂的处理过程, 函数调用过程为:
__qdisc_run -> qdisc_restart -> dequeue_skb -> htb_dequeue

htb_dequeue
	__skb_dequeue
	-> htb_do_events
	 -> htb_safe_rb_erase
	-> htb_change_class_mode
	-> htb_add_to_wait_tree
	-> htb_dequeue_tree
	-> htb_lookup_leaf
	-> htb_deactivate
	-> q->dequeue
	-> htb_next_rb_node
	-> htb_charge_class
	-> htb_change_class_mode
	-> htb_safe_rb_erase
	-> htb_add_to_wait_tree
	-> htb_delay_by
*/
static struct sk_buff *htb_dequeue(struct Qdisc *sch)
{
	struct sk_buff *skb = NULL;
	struct htb_sched *q = qdisc_priv(sch);
	int level;
	psched_time_t next_event;
	unsigned long start_at;

	/* try to dequeue direct packets as high prio (!) to minimize cpu work */
	skb = __skb_dequeue(&q->direct_queue); //先把不需要限速的SKB报文发送出去
	if (skb != NULL) {
		sch->flags &= ~TCQ_F_THROTTLED;// 取到数据包, 更新参数, 非阻塞, 返回
		sch->q.qlen--;
		return skb;
	}

	if (!sch->q.qlen)
		goto fin;
	q->now = psched_get_time();// 获取当前有效时间值
	start_at = jiffies;// 保存当前时间滴答数

	next_event = q->now + 5 * PSCHED_TICKS_PER_SEC;

	for (level = 0; level < TC_HTB_MAXDEPTH; level++) {// 遍历树的所有层次, 从叶子节点开始
		/* common case optimization - skip event handler quickly */
		int m;
		psched_time_t event;
     
        // 计算延迟值, 是取数据包失败的情况下更新HTB定时器的延迟时间
        // 比较ROW树中该层节点最近的事件定时时间是否已经到了 
		if (q->now >= q->near_ev_cache[level]) {
			event = htb_do_events(q, level, start_at);// 时间到了, 处理HTB事件, 返回值是下一个事件的延迟时间
			if (!event)
				event = q->now + PSCHED_TICKS_PER_SEC;
			q->near_ev_cache[level] = event;// 更新本层最近定时时间
		} else
			event = q->near_ev_cache[level];// 时间还没到, 计算两者时间差

        // 更新最小延迟值, 注意这是在循环里面进行更新的, 循环找出最小的延迟时间
		if (next_event > event)
			next_event = event;

        //该层次的row_mask取反, 实际是为找到row_mask[level]中为1的位, 为1表示该树有数据包可用
		m = ~q->row_mask[level];
		while (m != (int)(-1)) { //遍历每层level中的所有prio, q->row[level] + prio
            //m的数据位中第一个0位的位置作为优先级值, 从低位开始找, 也就是prio越小, 实际数据的优先权越大, 越先出队
			int prio = ffz(m);
			m |= 1 << prio;
            // 从该优先权值的流控树中进行出队操作HTB的流控就在该函数中体现
			skb = htb_dequeue_tree(q, prio, level);// 从指定的层次和优先权的RB树节点中取数据包
			if (likely(skb != NULL)) {
                // 数据包出队成功, 更新参数, 退出循环, 返回数据包
                // 取数据包成功就要去掉流控节点的阻塞标志
				sch->q.qlen--;
				sch->flags &= ~TCQ_F_THROTTLED;
				goto fin;
			}
		}
	}
	sch->qstats.overlimits++;
	if (likely(next_event > q->now))
		qdisc_watchdog_schedule(&q->watchdog, next_event);
	else
		schedule_work(&q->work);
fin:
	return skb;
}

/* try to drop from each class (by prio) until one succeed */
static unsigned int htb_drop(struct Qdisc *sch)
{
	struct htb_sched *q = qdisc_priv(sch);
	int prio;

	for (prio = TC_HTB_NUMPRIO - 1; prio >= 0; prio--) {// 遍历各个级别的丢包链表, 最先操作的是7号链表, 最后操作的是0号链表
		struct list_head *p;
		list_for_each(p, q->drops + prio) {
			struct htb_class *cl = list_entry(p, struct htb_class,
							  un.leaf.drop_list);
			unsigned int len;
			if (cl->un.leaf.q->ops->drop &&
			    (len = cl->un.leaf.q->ops->drop(cl->un.leaf.q))) {// 如果该类别的叶子节点流控定义了丢包操作, 进行相应丢包操作
				sch->q.qlen--;
				if (!cl->un.leaf.q->q.qlen)// 子流控节点为空, 停止该类别
					htb_deactivate(q, cl);
				return len;
			}
		}
	}
	return 0;
}

/* reset all classes */
/* always caled under BH & queue lock */
static void htb_reset(struct Qdisc *sch)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl;
	struct hlist_node *n;
	unsigned int i;

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode) {
			if (cl->level)
				memset(&cl->un.inner, 0, sizeof(cl->un.inner));
			else {
				if (cl->un.leaf.q)
					qdisc_reset(cl->un.leaf.q);
				INIT_LIST_HEAD(&cl->un.leaf.drop_list);
			}
			cl->prio_activity = 0;
			cl->cmode = HTB_CAN_SEND;

		}
	}
	qdisc_watchdog_cancel(&q->watchdog);
	__skb_queue_purge(&q->direct_queue);
	sch->q.qlen = 0;
	memset(q->row, 0, sizeof(q->row));
	memset(q->row_mask, 0, sizeof(q->row_mask));
	memset(q->wait_pq, 0, sizeof(q->wait_pq));
	memset(q->ptr, 0, sizeof(q->ptr));
	for (i = 0; i < TC_HTB_NUMPRIO; i++)
		INIT_LIST_HEAD(q->drops + i);
}

static const struct nla_policy htb_policy[TCA_HTB_MAX + 1] = {
	[TCA_HTB_PARMS]	= { .len = sizeof(struct tc_htb_opt) },
	[TCA_HTB_INIT]	= { .len = sizeof(struct tc_htb_glob) },
	[TCA_HTB_CTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
	[TCA_HTB_RTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
};

static void htb_work_func(struct work_struct *work)
{
	struct htb_sched *q = container_of(work, struct htb_sched, work);
	struct Qdisc *sch = q->watchdog.qdisc;

	__netif_schedule(qdisc_root(sch));
}

static int htb_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_HTB_INIT + 1];
	struct tc_htb_glob *gopt;
	int err;
	int i;

	if (!opt)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_HTB_INIT, opt, htb_policy);// 检查用户空间传过来的初始化数据的合法性
	if (err < 0)
		return err;

	if (tb[TCA_HTB_INIT] == NULL) {
		printk(KERN_ERR "HTB: hey probably you have bad tc tool ?\n");
		return -EINVAL;
	}
	gopt = nla_data(tb[TCA_HTB_INIT]);
	if (gopt->version != HTB_VER >> 16) {// 检查版本信息是否匹配
		printk(KERN_ERR
		       "HTB: need tc/htb version %d (minor is %d), you have %d\n",
		       HTB_VER >> 16, HTB_VER & 0xffff, gopt->version);
		return -EINVAL;
	}

	err = qdisc_class_hash_init(&q->clhash);
	if (err < 0)
		return err;
	for (i = 0; i < TC_HTB_NUMPRIO; i++)
		INIT_LIST_HEAD(q->drops + i);

	qdisc_watchdog_init(&q->watchdog, sch);
	INIT_WORK(&q->work, htb_work_func);
	skb_queue_head_init(&q->direct_queue);

	q->direct_qlen = qdisc_dev(sch)->tx_queue_len;
	if (q->direct_qlen < 2)	/* some devices have zero tx_queue_len */
		q->direct_qlen = 2;

	if ((q->rate2quantum = gopt->rate2quantum) < 1) // 流量到定额转换参数, 是TC命令中的r2q参数
		q->rate2quantum = 1;
	q->defcls = gopt->defcls;// 缺省类别

	return 0;
}

//输出HTB参数
static int htb_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	spinlock_t *root_lock = qdisc_root_sleeping_lock(sch);
	struct htb_sched *q = qdisc_priv(sch);
	struct nlattr *nest;
	struct tc_htb_glob gopt;

	spin_lock_bh(root_lock);

	gopt.direct_pkts = q->direct_pkts;// 直接发送的数据包数量
	gopt.version = HTB_VER;
	gopt.rate2quantum = q->rate2quantum;
	gopt.defcls = q->defcls;
	gopt.debug = 0;

    // 返回数据在数据包中的具体位置
	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;
	NLA_PUT(skb, TCA_HTB_INIT, sizeof(gopt), &gopt);// 填入选项参数
	nla_nest_end(skb, nest);

	spin_unlock_bh(root_lock);
	return skb->len;

nla_put_failure:
	spin_unlock_bh(root_lock);
	nla_nest_cancel(skb, nest);
	return -1;
}
/*
root@mc_core:~# tc class show dev eth0
class htb 2:3 root prio 0 rate 328bit ceil 4440bit burst 1599b cburst 1599b 
*///应用层通过tc class show获取htb参数信息
static int htb_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct htb_class *cl = (struct htb_class *)arg;
	spinlock_t *root_lock = qdisc_root_sleeping_lock(sch);
	struct nlattr *nest;
	struct tc_htb_opt opt;

	spin_lock_bh(root_lock);
	// 父节点的类别ID
	tcm->tcm_parent = cl->parent ? cl->parent->common.classid : TC_H_ROOT;
	// 本节点的类别ID
	tcm->tcm_handle = cl->common.classid;
	if (!cl->level && cl->un.leaf.q)// 如果是叶子节点, 提供叶子节点的流控节点的ID
		tcm->tcm_info = cl->un.leaf.q->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	memset(&opt, 0, sizeof(opt));// 以下提供该类别的各种参数

	opt.rate = cl->rate->rate;// 速率
	opt.buffer = cl->buffer;// 数据缓冲区
	opt.ceil = cl->ceil->rate;// 峰值速率
	opt.cbuffer = cl->cbuffer;// 峰值数据缓冲区
	opt.quantum = cl->quantum;// 定额
	opt.prio = cl->prio;
	opt.level = cl->level;// 层次值
	NLA_PUT(skb, TCA_HTB_PARMS, sizeof(opt), &opt);

	nla_nest_end(skb, nest);// 实际数据长度
	spin_unlock_bh(root_lock);
	return skb->len;

nla_put_failure:
	spin_unlock_bh(root_lock);
	nla_nest_cancel(skb, nest);
	return -1;
}

//应用层tc -s qdisc ls dev eth0    类别统计信息输出 
static int
htb_dump_class_stats(struct Qdisc *sch, unsigned long arg, struct gnet_dump *d)
{
	struct htb_class *cl = (struct htb_class *)arg;

	if (!cl->level && cl->un.leaf.q)// 叶子节点, 提供当前内部流控结构的队列长度
		cl->qstats.qlen = cl->un.leaf.q->q.qlen;
	cl->xstats.tokens = cl->tokens; //当前令牌数
	cl->xstats.ctokens = cl->ctokens;// 峰值令牌数

    // 分别将基本参数, 速率参数, 队列参数拷贝到目的缓存, 这些都是标准参数
	if (gnet_stats_copy_basic(d, &cl->bstats) < 0 ||
	    gnet_stats_copy_rate_est(d, NULL, &cl->rate_est) < 0 ||
	    gnet_stats_copy_queue(d, &cl->qstats) < 0)
		return -1;

    // 将应用数据(HTB自身统计数据)拷贝到目的缓存
	return gnet_stats_copy_app(d, &cl->xstats, sizeof(cl->xstats));
}

//使用htb_graft()函数来设置叶子节点的流控方法.

static int htb_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct htb_class *cl = (struct htb_class *)arg;

	if (cl->level)// 类别结构非空而且层次为0(叶子节点)
		return -EINVAL;
	if (new == NULL &&
	    (new = qdisc_create_dflt(qdisc_dev(sch), sch->dev_queue,
				     &pfifo_qdisc_ops,
				     cl->common.classid)) == NULL)// 如果没定义专门的流控方法, 则缺省定义pfifo作为缺省的流控方法
		return -ENOBUFS;

	sch_tree_lock(sch);
	*old = cl->un.leaf.q;
	cl->un.leaf.q = new;// 将新的流控方法作为类别结构叶子节点的流控方法
	if (*old != NULL) {
        // 如果该类别还处于活动状态, 停止, 因为其原来的流控方法已经要被释放掉, 
        // 不再处理数据包
		qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
		qdisc_reset(*old);// 将老流控节点释放掉
	}
	sch_tree_unlock(sch);
	return 0;
}

//在内核中会使用htb_leaf()查找HTB叶子节点
static struct Qdisc *htb_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct htb_class *cl = (struct htb_class *)arg;
	return !cl->level ? cl->un.leaf.q : NULL;// 如果类别结构非空而且是叶子节点, 返回该类别叶子节点的流控
}

static void htb_qlen_notify(struct Qdisc *sch, unsigned long arg)
{
	struct htb_class *cl = (struct htb_class *)arg;

	if (cl->un.leaf.q->q.qlen == 0)
		htb_deactivate(qdisc_priv(sch), cl);
}

//根据tc class add parent 3 classid 3:4中的classid 3:4找到对应的内核分类信息结构htb_class，并把地址强制转换为long类型
static unsigned long htb_get(struct Qdisc *sch, u32 classid) //增加类别的引用计数,减少htb_put
{
	struct htb_class *cl = htb_find(classid, sch);
	if (cl)
		cl->refcnt++;
	return (unsigned long)cl;
}

static inline int htb_parent_last_child(struct htb_class *cl)
{
	if (!cl->parent)
		/* the root class */
		return 0;
	if (cl->parent->children > 1)
		/* not the last child */
		return 0;
	return 1;
}

static void htb_parent_to_leaf(struct htb_sched *q, struct htb_class *cl,
			       struct Qdisc *new_q)
{
	struct htb_class *parent = cl->parent;

	WARN_ON(cl->level || !cl->un.leaf.q || cl->prio_activity);

	if (parent->cmode != HTB_CAN_SEND)
		htb_safe_rb_erase(&parent->pq_node, q->wait_pq + parent->level);

	parent->level = 0;
	memset(&parent->un.inner, 0, sizeof(parent->un.inner));
	INIT_LIST_HEAD(&parent->un.leaf.drop_list);
	parent->un.leaf.q = new_q ? new_q : &noop_qdisc;
	parent->tokens = parent->buffer;
	parent->ctokens = parent->cbuffer;
	parent->t_c = psched_get_time();
	parent->cmode = HTB_CAN_SEND;
}

static void htb_destroy_class(struct Qdisc *sch, struct htb_class *cl)
{
	if (!cl->level) {
		WARN_ON(!cl->un.leaf.q);
		qdisc_destroy(cl->un.leaf.q);
	}
	gen_kill_estimator(&cl->bstats, &cl->rate_est);
	qdisc_put_rtab(cl->rate);
	qdisc_put_rtab(cl->ceil);

	tcf_destroy_chain(&cl->filter_list);
	kfree(cl);
}

static void htb_destroy(struct Qdisc *sch)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct hlist_node *n, *next;
	struct htb_class *cl;
	unsigned int i;

	cancel_work_sync(&q->work);
	qdisc_watchdog_cancel(&q->watchdog);
	/* This line used to be after htb_destroy_class call below
	   and surprisingly it worked in 2.4. But it must precede it
	   because filter need its target class alive to be able to call
	   unbind_filter on it (without Oops). */
	tcf_destroy_chain(&q->filter_list);

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode)
			tcf_destroy_chain(&cl->filter_list);
	}
	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry_safe(cl, n, next, &q->clhash.hash[i],
					  common.hnode)
			htb_destroy_class(sch, cl);
	}
	qdisc_class_hash_destroy(&q->clhash);
	__skb_queue_purge(&q->direct_queue);
}

static int htb_delete(struct Qdisc *sch, unsigned long arg)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl = (struct htb_class *)arg;
	unsigned int qlen;
	struct Qdisc *new_q = NULL;
	int last_child = 0;

	// TODO: why don't allow to delete subtree ? references ? does
	// tc subsys quarantee us that in htb_destroy it holds no class
	// refs so that we can remove children safely there ?
	if (cl->children || cl->filter_cnt)
		return -EBUSY;

	if (!cl->level && htb_parent_last_child(cl)) {
		new_q = qdisc_create_dflt(qdisc_dev(sch), sch->dev_queue,
					  &pfifo_qdisc_ops,
					  cl->parent->common.classid);
		last_child = 1;
	}

	sch_tree_lock(sch);

	if (!cl->level) {
		qlen = cl->un.leaf.q->q.qlen;
		qdisc_reset(cl->un.leaf.q);
		qdisc_tree_decrease_qlen(cl->un.leaf.q, qlen);
	}

	/* delete from hash and active; remainder in destroy_class */
	qdisc_class_hash_remove(&q->clhash, &cl->common);
	if (cl->parent)
		cl->parent->children--;

	if (cl->prio_activity)
		htb_deactivate(q, cl);

	if (cl->cmode != HTB_CAN_SEND)
		htb_safe_rb_erase(&cl->pq_node, q->wait_pq + cl->level);

	if (last_child)
		htb_parent_to_leaf(q, cl, new_q);

	BUG_ON(--cl->refcnt == 0);
	/*
	 * This shouldn't happen: we "hold" one cops->get() when called
	 * from tc_ctl_tclass; the destroy method is done from cops->put().
	 */

	sch_tree_unlock(sch);
	return 0;
}

static void htb_put(struct Qdisc *sch, unsigned long arg)
{
	struct htb_class *cl = (struct htb_class *)arg;

	if (--cl->refcnt == 0)
		htb_destroy_class(sch, cl);
}

//更改类别结构内部参数
static int htb_change_class(struct Qdisc *sch, u32 classid,
			    u32 parentid, struct nlattr **tca,
			    unsigned long *arg)
{
	int err = -EINVAL;
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl = (struct htb_class *)*arg, *parent;// 类别结构指针, 从上层传入
	struct nlattr *opt = tca[TCA_OPTIONS];// 通过netlink接口传来的配置参数
	struct qdisc_rate_table *rtab = NULL, *ctab = NULL;// 速率表, 峰值速率表结构
	struct nlattr *tb[TCA_HTB_RTAB + 1];// 保存解析后的参数
	struct tc_htb_opt *hopt;// HTB选项

	/* extract all subattrs from opt attr */
	if (!opt)
		goto failure;

	err = nla_parse_nested(tb, TCA_HTB_RTAB, opt, htb_policy);// 解析输入参数, 进行相关合法性检查
	if (err < 0)
		goto failure;

	err = -EINVAL;
	if (tb[TCA_HTB_PARMS] == NULL)
		goto failure;

    // 如果父节点ID不是根ID, 根据此ID查找父节点, 否则为父节点空
	parent = parentid == TC_H_ROOT ? NULL : htb_find(parentid, sch);

	hopt = nla_data(tb[TCA_HTB_PARMS]);

    // 从输入参数中获取速率表结构: 普通速率和峰值速率
	rtab = qdisc_get_rtab(&hopt->rate, tb[TCA_HTB_RTAB]);
	ctab = qdisc_get_rtab(&hopt->ceil, tb[TCA_HTB_CTAB]);
	if (!rtab || !ctab)
		goto failure;

	if (!cl) {		/* new class */ //cl为空，表示需要创建一个class类，不为空表示是修改class参数
		struct Qdisc *new_q;
		int prio;
		struct {
			struct nlattr		nla;
			struct gnet_estimator	opt;
		} est = {
			.nla = {
				.nla_len	= nla_attr_size(sizeof(est.opt)),
				.nla_type	= TCA_RATE,
			},
			.opt = {
				/* 4s interval, 16s averaging constant */
				.interval	= 2,
				.ewma_log	= 2,
			},
		};

		/* check for valid classid */
		if (!classid || TC_H_MAJ(classid ^ sch->handle) ||
		    htb_find(classid, sch))// 类别ID合法性检查
			goto failure;

		/* check maximal depth */// 如果祖父节点层次都小于2, 也就是最大是1, 表示HTB节点树太深了, 叶子节点都没法表示了
		if (parent && parent->parent && parent->parent->level < 2) {
			printk(KERN_ERR "htb: tree is too deep\n");
			goto failure;
		}
		err = -ENOBUFS;
		if ((cl = kzalloc(sizeof(*cl), GFP_KERNEL)) == NULL) //为htb_class分类信息分配空间
			goto failure;

		err = gen_new_estimator(&cl->bstats, &cl->rate_est,
					qdisc_root_sleeping_lock(sch),
					tca[TCA_RATE] ? : &est.nla);
		if (err) {
			kfree(cl);
			goto failure;
		}

		cl->refcnt = 1;// 初始化引用计数
		cl->children = 0;
		INIT_LIST_HEAD(&cl->un.leaf.drop_list);// 初始化丢包链表
		RB_CLEAR_NODE(&cl->pq_node);// 设置为空节点(父节点是本身)

		for (prio = 0; prio < TC_HTB_NUMPRIO; prio++)
			RB_CLEAR_NODE(&cl->node[prio]);// 初始化self or feed tree节点

		/* create leaf qdisc early because it uses kmalloc(GFP_KERNEL)
		   so that can't be used inside of sch_tree_lock
		   -- thanks to Karlis Peisenieks */
		new_q = qdisc_create_dflt(qdisc_dev(sch), sch->dev_queue,
					  &pfifo_qdisc_ops, classid);// 新的流控节点缺省是使用pfifo
		sch_tree_lock(sch);
		if (parent && !parent->level) { // 如果父节点原先是叶子节点, 将其转为中间节点, 因为现在已经有新的叶子节点作为其子节点
			unsigned int qlen = parent->un.leaf.q->q.qlen;

			/* turn parent into inner node */
			qdisc_reset(parent->un.leaf.q);// 释放父节点的流控结构
			qdisc_tree_decrease_qlen(parent->un.leaf.q, qlen);
			qdisc_destroy(parent->un.leaf.q);
			if (parent->prio_activity)// 如果该父节点正处于活动情况, 停止
				htb_deactivate(q, parent);

			/* remove from evt list because of level change */
			if (parent->cmode != HTB_CAN_SEND) {// 如果不是HTB_CAN_SEND模式, 说明该节点在等待节点树中, 从该树中删除
				htb_safe_rb_erase(&parent->pq_node, q->wait_pq);
				parent->cmode = HTB_CAN_SEND;
			}
			parent->level = (parent->parent ? parent->parent->level
					 : TC_HTB_MAXDEPTH) - 1;
		    // 不再使用内部叶子结构, 而是改为使用HTB内部结构, 参数清零
			memset(&parent->un.inner, 0, sizeof(parent->un.inner));
		}
		/* leaf (we) needs elementary qdisc */
		cl->un.leaf.q = new_q ? new_q : &noop_qdisc;// 设置类别结构的叶子流控节点

        // 类别结构的ID和父
		cl->common.classid = classid;
		cl->parent = parent;

		/* set class to be in HTB_CAN_SEND state */ // 令牌和峰值令牌
		cl->tokens = hopt->buffer;
		cl->ctokens = hopt->cbuffer;
		cl->mbuffer = 60 * PSCHED_TICKS_PER_SEC;	/* 1min */ // 缓冲区大小
		cl->t_c = psched_get_time();// 初始化时间
		cl->cmode = HTB_CAN_SEND;

		/* attach to the hash list and parent's family */
		qdisc_class_hash_insert(&q->clhash, &cl->common);// 挂接到哈希链表
		if (parent)
			parent->children++;
	} else {
		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, &cl->rate_est,
						    qdisc_root_sleeping_lock(sch),
						    tca[TCA_RATE]);
			if (err)
				return err;
		}
		sch_tree_lock(sch);
	}

	/* it used to be a nasty bug here, we have to check that node
	   is really leaf before changing cl->un.leaf ! */
	if (!cl->level) {// 如果是叶子节点, 设置其定额, 当出现赤字时会按定额大小增加
		cl->quantum = rtab->rate.rate / q->rate2quantum;
		if (!hopt->quantum && cl->quantum < 1000) {
			printk(KERN_WARNING
			       "HTB: quantum of class %X is small. Consider r2q change.\n",
			       cl->common.classid);
			cl->quantum = 1000;
		}

		// 如果计算出的定额量太小或太大, 说明rate2quantum参数该调整了, 这就是tc命令中的r2q参数
		if (!hopt->quantum && cl->quantum > 200000) {
			printk(KERN_WARNING
			       "HTB: quantum of class %X is big. Consider r2q change.\n",
			       cl->common.classid);
			cl->quantum = 200000;
		}
		if (hopt->quantum)
			cl->quantum = hopt->quantum;
			
		if ((cl->prio = hopt->prio) >= TC_HTB_NUMPRIO)
			cl->prio = TC_HTB_NUMPRIO - 1;
	}

	cl->buffer = hopt->buffer;
	cl->cbuffer = hopt->cbuffer;
	if (cl->rate)
		qdisc_put_rtab(cl->rate);
	cl->rate = rtab;
	// 峰值速率控制结构更新
	if (cl->ceil)
		qdisc_put_rtab(cl->ceil);
	cl->ceil = ctab;
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;

failure:
	if (rtab)
		qdisc_put_rtab(rtab);
	if (ctab)
		qdisc_put_rtab(ctab);
	return err;
}

//查找过滤规则表
static struct tcf_proto **htb_find_tcf(struct Qdisc *sch, unsigned long arg)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl = (struct htb_class *)arg;
	// 如果类别结构非空,使用类别结构的过滤表, 否则使用HTB私有结构的过滤表
	struct tcf_proto **fl = cl ? &cl->filter_list : &q->filter_list;

	return fl;
}

static unsigned long htb_bind_filter(struct Qdisc *sch, unsigned long parent,
				     u32 classid)
{
	struct htb_class *cl = htb_find(classid, sch);// 根据类别ID查找类别结构

	/*if (cl && !cl->level) return 0;
	   The line above used to be there to prevent attaching filters to
	   leaves. But at least tc_index filter uses this just to get class
	   for other reasons so that we have to allow for it.
	   ----
	   19.6.2002 As Werner explained it is ok - bind filter is just
	   another way to "lock" the class - unlike "get" this lock can
	   be broken by class during destroy IIUC.
	 */
	if (cl)// 如果流控类别结构有效, 增加其使用计数
		cl->filter_cnt++;
	return (unsigned long)cl;
}

static void htb_unbind_filter(struct Qdisc *sch, unsigned long arg)
{
	struct htb_class *cl = (struct htb_class *)arg;

	if (cl)
		cl->filter_cnt--;
}

//rtnl_register -> rtnl_dump_all中在收到rtlnetlink应用层配置信息的时候会执行cb->fn ,见rtnetlink_init -> rtnl_dump_all
//遍历HTB,执行对应的fn
static void htb_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct htb_sched *q = qdisc_priv(sch);
	struct htb_class *cl;
	struct hlist_node *n;
	unsigned int i;

	if (arg->stop)// 如果设置停止标志, 返回
		return;

	for (i = 0; i < q->clhash.hashsize; i++) {// 遍历所有HTB哈希表

	    // 遍历哈希表中每个元素, 即HTB类别结构
		hlist_for_each_entry(cl, n, &q->clhash.hash[i], common.hnode) {
			if (arg->count < arg->skip) {// 如果要跳过skip个开始的一些节点, 跳过这些节点
				arg->count++;
				continue;
			}
			if (arg->fn(sch, (unsigned long)cl, arg) < 0) { //函数为qdisc_class_dump  见tc_dump_tclass_qdisc
				arg->stop = 1;
				return;
			}
			arg->count++;
		}
	}
}

//prio对应prio_class_ops htb对应htb_class_ops cbq对应cbq_class_ops等等
static const struct Qdisc_class_ops htb_class_ops = { //tcf一般表示tcf_proto过滤器
	.graft		=	htb_graft,
	.leaf		=	htb_leaf,
	.qlen_notify	=	htb_qlen_notify,
	.get		=	htb_get,
	.put		=	htb_put,
	.change		=	htb_change_class,
	.delete		=	htb_delete,
	.walk		=	htb_walk,
	.tcf_chain	=	htb_find_tcf,  
	.bind_tcf	=	htb_bind_filter,
	.unbind_tcf	=	htb_unbind_filter,
	.dump		=	htb_dump_class,
	.dump_stats	=	htb_dump_class_stats,
};

//HTB(分层令牌桶)可以参考:RouterOS QoS HTB流控原理  HTB分层令牌桶排队规则分析
static struct Qdisc_ops htb_qdisc_ops {//__read_mostly = { 参考<HTB介绍以及使用.doc>
	.next		=	NULL,
	.cl_ops		=	&htb_class_ops,
	.id		=	"htb",
	.priv_size	=	sizeof(struct htb_sched),
	.enqueue	=	htb_enqueue,
	.dequeue	=	htb_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.drop		=	htb_drop,
	.init		=	htb_init,
	.reset		=	htb_reset,
	.destroy	=	htb_destroy,
	.change		=	NULL /* htb_change */,
	.dump		=	htb_dump,
	.owner		=	THIS_MODULE,
};

static int __init htb_module_init(void)
{
	return register_qdisc(&htb_qdisc_ops);
}
static void __exit htb_module_exit(void)
{
	unregister_qdisc(&htb_qdisc_ops);
}

module_init(htb_module_init)
module_exit(htb_module_exit)
MODULE_LICENSE("GPL");

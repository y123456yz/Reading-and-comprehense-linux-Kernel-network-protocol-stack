/*
 * net/sched/cls_u32.c	Ugly (or Universal) 32bit key Packet Classifier.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *	The filters are packed to hash tables of key nodes
 *	with a set of 32bit key/mask pairs at every node.
 *	Nodes reference next level hash tables etc.
 *
 *	This scheme is the best universal classifier I managed to
 *	invent; it is not super-fast, but it is not slow (provided you
 *	program it correctly), and general enough.  And its relative
 *	speed grows as the number of rules becomes larger.
 *
 *	It seems that it represents the best middle point between
 *	speed and manageability both by human and by machine.
 *
 *	It is especially useful for link sharing combined with QoS;
 *	pure RSVP doesn't need such a general approach and can use
 *	much simpler (and faster) schemes, sort of cls_rsvp.c.
 *
 *	JHS: We should remove the CONFIG_NET_CLS_IND from here
 *	eventually when the meta match extension is made available
 *
 *	nfmark match added by Catalin(ux aka Dino) BOIE <catab at umbrella.ro>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/act_api.h>
#include <net/pkt_cls.h>

//图形化理解参考参考TC流量控制实现分析(初步)*/   //详细理解也可以参考<<LINUX高级路由和流量控制>>
//tc_u_hnode里面的ht指向这里 tc filter u32过滤器的结构,起源结构在tcf_proto
/*一个tc_u_hnode上面可能包含多条的过滤信息，例如添加过滤器的时候可以过滤源 目的 IP port mask等，每个信息都存在于tc_u_common
的tc_u_knode数组ht[]中，然后这些多条一起添加到tc_u_hnode，参考u32_init。例如tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 xxxx后，
继续添加tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32，这样添加好几条针对parent 1:0的过滤器tc_u_common*/
struct tc_u_knode
{
	struct tc_u_knode	*next;
	u32			handle;
	struct tc_u_hnode	*ht_up;
	struct tcf_exts		exts;
#ifdef CONFIG_NET_CLS_IND
	char                     indev[IFNAMSIZ];
#endif
	u8			fshift;
	struct tcf_result	res; //u32过滤器在匹配SKB内容的时候，结果返回给该值
	struct tc_u_hnode	*ht_down;
#ifdef CONFIG_CLS_U32_PERF
	struct tc_u32_pcnt	*pf;
#endif
#ifdef CONFIG_CLS_U32_MARK
	struct tc_u32_mark	mark;
#endif
	struct tc_u32_sel	sel;
}; //该结构是加入到prio_sched_data中的filter_list链表中  每调用一次tc filter add就会创建一个tcf_proto结构，调用多个tc filter add的时候就创建多个tcf_proto结构，通过next连接

//图形化理解参考参考TC流量控制实现分析(初步)*/   //详细理解也可以参考<<LINUX高级路由和流量控制>>
//tcf_proto里面的root指向这里 tc filter u32过滤器的结构,起源结构在tcf_proto的root
struct tc_u_hnode  //u32过滤器在u32_init中创建并初始化。 新建的所有tc_u_common都通过next添加到该过滤器跟表上
/*一个tc_u_hnode上面可能包含多条的过滤信息，例如添加过滤器的时候可以过滤源 目的 IP port mask等，每个信息都存在于tc_u_common
的tc_u_knode数组ht[]中，然后这些多条一起添加到tc_u_hnode，参考u32_init。例如tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 xxxx后，
继续添加tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32，添加两个tc filter add就会创建两个tcf_proto过滤器结构，但是每条里面针对parent 1:0的过滤器tc_u_common*/
{
	struct tc_u_hnode	*next;//通过这个指向对应跟下面所有tc_u_common节点的最后一个tc_u_common节点，参考u32_init
	u32			handle; //为过滤器自动分配的一个handle
	u32			prio;//tc filter add dev eth0 protocol ip parent 22: prio 2为2
	struct tc_u_common	*tp_c; //指向最后创建的uc_u_common过滤器
	int			refcnt;
	unsigned		divisor;
	struct tc_u_knode	*ht[1];//这是每条过滤器中的多条过滤因子，如一条过滤器中可能包含多个ip mask port等，可以通过该结构组织
};

//图形化理解参考参考TC流量控制实现分析(初步)*/   //详细理解也可以参考<<LINUX高级路由和流量控制>>
//tcf_proto里面的data指向这里   tc filter u32过滤器的结构,起源结构在tcf_proto的data
////一个tc_u_hnode上面可能包含很多的过滤信息，例如添加过滤器的时候可以过滤源 目的 IP port mask等，每个信息都存在于tc_u_common，然后一起添加到tc_u_hnode，参考u32_init
/*一个tc_u_hnode上面可能包含多条的过滤信息，例如添加过滤器的时候可以过滤源 目的 IP port mask等，每个信息都存在于tc_u_common
的tc_u_knode数组ht[]中，然后这些多条一起添加到tc_u_hnode，参考u32_init。例如tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 xxxx后，
继续添加tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32，这样添加好2条针对parent 1:0的过滤器tc_u_common*/
struct tc_u_common
{
	struct tc_u_hnode	*hlist;//通过这个指向tc_u_hnode跟
	struct Qdisc		*q;
	int			refcnt;
	u32			hgenerator;
};

static const struct tcf_ext_map u32_ext_map = {
	.action = TCA_U32_ACT,
	.police = TCA_U32_POLICE
};

static __inline__ unsigned u32_hash_fold(__be32 key, struct tc_u32_sel *sel, u8 fshift)
{
	unsigned h = ntohl(key & sel->hmask)>>fshift;

	return h;
}

////U32分类函数，结果保存在tcf_result中。通过SKB中的内容，来匹配这个过滤器，结果返回给tcf_result，见tc_classify_compat
//匹配成功返回0，并把匹配到的过滤器所处的子分类信息节点存到res中
static int u32_classify(struct sk_buff *skb, struct tcf_proto *tp, struct tcf_result *res)
{
	struct {
		struct tc_u_knode *knode;
		unsigned int	  off;
	} stack[TC_U32_MAXDEPTH];

	struct tc_u_hnode *ht = (struct tc_u_hnode*)tp->root;
	unsigned int off = skb_network_offset(skb);
	struct tc_u_knode *n;
	int sdepth = 0;
	int off2 = 0;
	int sel = 0;
#ifdef CONFIG_CLS_U32_PERF
	int j;
#endif
	int i, r;

next_ht:
	n = ht->ht[sel];

next_knode:
	if (n) {
		struct tc_u32_key *key = n->sel.keys;

#ifdef CONFIG_CLS_U32_PERF
		n->pf->rcnt +=1;
		j = 0;
#endif

#ifdef CONFIG_CLS_U32_MARK
		if ((skb->mark & n->mark.mask) != n->mark.val) {
			n = n->next;
			goto next_knode;
		} else {
			n->mark.success++;
		}
#endif

		for (i = n->sel.nkeys; i>0; i--, key++) {
			unsigned int toff;
			__be32 *data, _data;

			toff = off + key->off + (off2 & key->offmask);
			data = skb_header_pointer(skb, toff, 4, &_data);
			if (!data)
				goto out;
			if ((*data ^ key->val) & key->mask) {
				n = n->next;
				goto next_knode;
			}
#ifdef CONFIG_CLS_U32_PERF
			n->pf->kcnts[j] +=1;
			j++;
#endif
		}
		if (n->ht_down == NULL) {
check_terminal:
			if (n->sel.flags&TC_U32_TERMINAL) {

				*res = n->res;
#ifdef CONFIG_NET_CLS_IND
				if (!tcf_match_indev(skb, n->indev)) {
					n = n->next;
					goto next_knode;
				}
#endif
#ifdef CONFIG_CLS_U32_PERF
				n->pf->rhit +=1;
#endif
				r = tcf_exts_exec(skb, &n->exts, res);
				if (r < 0) {
					n = n->next;
					goto next_knode;
				}

				return r;
			}
			n = n->next;
			goto next_knode;
		}

		/* PUSH */
		if (sdepth >= TC_U32_MAXDEPTH)
			goto deadloop;
		stack[sdepth].knode = n;
		stack[sdepth].off = off;
		sdepth++;

		ht = n->ht_down;
		sel = 0;
		if (ht->divisor) {
			__be32 *data, _data;

			data = skb_header_pointer(skb, off + n->sel.hoff, 4,
						  &_data);
			if (!data)
				goto out;
			sel = ht->divisor & u32_hash_fold(*data, &n->sel,
							  n->fshift);
		}
		if (!(n->sel.flags&(TC_U32_VAROFFSET|TC_U32_OFFSET|TC_U32_EAT)))
			goto next_ht;

		if (n->sel.flags&(TC_U32_OFFSET|TC_U32_VAROFFSET)) {
			off2 = n->sel.off + 3;
			if (n->sel.flags & TC_U32_VAROFFSET) {
				__be16 *data, _data;

				data = skb_header_pointer(skb,
							  off + n->sel.offoff,
							  2, &_data);
				if (!data)
					goto out;
				off2 += ntohs(n->sel.offmask & *data) >>
					n->sel.offshift;
			}
			off2 &= ~3;
		}
		if (n->sel.flags&TC_U32_EAT) {
			off += off2;
			off2 = 0;
		}

		if (off < skb->len)
			goto next_ht;
	}

	/* POP */
	if (sdepth--) {
		n = stack[sdepth].knode;
		ht = n->ht_up;
		off = stack[sdepth].off;
		goto check_terminal;
	}
out:
	return -1;

deadloop:
	if (net_ratelimit())
		printk(KERN_WARNING "cls_u32: dead loop\n");
	return -1;
}

static __inline__ struct tc_u_hnode *
u32_lookup_ht(struct tc_u_common *tp_c, u32 handle)
{
	struct tc_u_hnode *ht;

	for (ht = tp_c->hlist; ht; ht = ht->next)
		if (ht->handle == handle)
			break;

	return ht;
}

static __inline__ struct tc_u_knode *
u32_lookup_key(struct tc_u_hnode *ht, u32 handle)
{
	unsigned sel;
	struct tc_u_knode *n = NULL;

	sel = TC_U32_HASH(handle);
	if (sel > ht->divisor)
		goto out;

	for (n = ht->ht[sel]; n; n = n->next)
		if (n->handle == handle)
			break;
out:
	return n;
}

//获取tcf_proto(tc filter add的时候创建一个该类型过滤器) //讲一个过滤器元素的句柄映射到一个内部过滤器标识符，实际上是过滤器实例指针，并将其返回
//tp为
static unsigned long u32_get(struct tcf_proto *tp, u32 handle)
{
	struct tc_u_hnode *ht;
	struct tc_u_common *tp_c = tp->data;

	if (TC_U32_HTID(handle) == TC_U32_ROOT)
		ht = tp->root;
	else
		ht = u32_lookup_ht(tp_c, TC_U32_HTID(handle));

	if (!ht)
		return 0;

	if (TC_U32_KEY(handle) == 0)
		return (unsigned long)ht;

	return (unsigned long)u32_lookup_key(ht, handle);
}

static void u32_put(struct tcf_proto *tp, unsigned long f)
{
}

static u32 gen_new_htid(struct tc_u_common *tp_c)
{
	int i = 0x800;

	do {
		if (++tp_c->hgenerator == 0x7FF)
			tp_c->hgenerator = 1;
	} while (--i>0 && u32_lookup_ht(tp_c, (tp_c->hgenerator|0x800)<<20));

	return i > 0 ? (tp_c->hgenerator|0x800)<<20 : 0;
}

// tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4
static int u32_init(struct tcf_proto *tp)//tc_ctl_tclass调用
{
	struct tc_u_hnode *root_ht;
	struct tc_u_common *tp_c;

	tp_c = tp->q->u32_node;

	root_ht = kzalloc(sizeof(*root_ht), GFP_KERNEL);
	if (root_ht == NULL)
		return -ENOBUFS;

	root_ht->divisor = 0;
	root_ht->refcnt++;
	root_ht->handle = tp_c ? gen_new_htid(tp_c) : 0x80000000;
	root_ht->prio = tp->prio;//tc filter add dev eth0 protocol ip parent 22: prio 2为2

	if (tp_c == NULL) {
		tp_c = kzalloc(sizeof(*tp_c), GFP_KERNEL);
		if (tp_c == NULL) {
			kfree(root_ht);
			return -ENOBUFS;
		}
		tp_c->q = tp->q;
		tp->q->u32_node = tp_c;
	}

	tp_c->refcnt++;

	//通过这个把tc_u_common添加到跟tc_u_hnode的尾节点上
	root_ht->next = tp_c->hlist;
	tp_c->hlist = root_ht;
	root_ht->tp_c = tp_c;

    //
	tp->root = root_ht;
	tp->data = tp_c;
	return 0;
}

static int u32_destroy_key(struct tcf_proto *tp, struct tc_u_knode *n)
{
	tcf_unbind_filter(tp, &n->res);
	tcf_exts_destroy(tp, &n->exts);
	if (n->ht_down)
		n->ht_down->refcnt--;
#ifdef CONFIG_CLS_U32_PERF
	kfree(n->pf);
#endif
	kfree(n);
	return 0;
}

static int u32_delete_key(struct tcf_proto *tp, struct tc_u_knode* key)
{
	struct tc_u_knode **kp;
	struct tc_u_hnode *ht = key->ht_up;

	if (ht) {
		for (kp = &ht->ht[TC_U32_HASH(key->handle)]; *kp; kp = &(*kp)->next) {
			if (*kp == key) {
				tcf_tree_lock(tp);
				*kp = key->next;
				tcf_tree_unlock(tp);

				u32_destroy_key(tp, key);
				return 0;
			}
		}
	}
	WARN_ON(1);
	return 0;
}

static void u32_clear_hnode(struct tcf_proto *tp, struct tc_u_hnode *ht)
{
	struct tc_u_knode *n;
	unsigned h;

	for (h=0; h<=ht->divisor; h++) {
		while ((n = ht->ht[h]) != NULL) {
			ht->ht[h] = n->next;

			u32_destroy_key(tp, n);
		}
	}
}

static int u32_destroy_hnode(struct tcf_proto *tp, struct tc_u_hnode *ht)
{
	struct tc_u_common *tp_c = tp->data;
	struct tc_u_hnode **hn;

	WARN_ON(ht->refcnt);

	u32_clear_hnode(tp, ht);

	for (hn = &tp_c->hlist; *hn; hn = &(*hn)->next) {
		if (*hn == ht) {
			*hn = ht->next;
			kfree(ht);
			return 0;
		}
	}

	WARN_ON(1);
	return -ENOENT;
}

static void u32_destroy(struct tcf_proto *tp)
{
	struct tc_u_common *tp_c = tp->data;
	struct tc_u_hnode *root_ht = tp->root;

	WARN_ON(root_ht == NULL);

	if (root_ht && --root_ht->refcnt == 0)
		u32_destroy_hnode(tp, root_ht);

	if (--tp_c->refcnt == 0) {
		struct tc_u_hnode *ht;

		tp->q->u32_node = NULL;

		for (ht = tp_c->hlist; ht; ht = ht->next) {
			ht->refcnt--;
			u32_clear_hnode(tp, ht);
		}

		while ((ht = tp_c->hlist) != NULL) {
			tp_c->hlist = ht->next;

			WARN_ON(ht->refcnt != 0);

			kfree(ht);
		}

		kfree(tp_c);
	}

	tp->data = NULL;
}

static int u32_delete(struct tcf_proto *tp, unsigned long arg)
{
	struct tc_u_hnode *ht = (struct tc_u_hnode*)arg;

	if (ht == NULL)
		return 0;

	if (TC_U32_KEY(ht->handle))
		return u32_delete_key(tp, (struct tc_u_knode*)ht);

	if (tp->root == ht)
		return -EINVAL;

	if (ht->refcnt == 1) {
		ht->refcnt--;
		u32_destroy_hnode(tp, ht);
	} else {
		return -EBUSY;
	}

	return 0;
}

static u32 gen_new_kid(struct tc_u_hnode *ht, u32 handle)
{
	struct tc_u_knode *n;
	unsigned i = 0x7FF;

	for (n=ht->ht[TC_U32_HASH(handle)]; n; n = n->next)
		if (i < TC_U32_NODE(n->handle))
			i = TC_U32_NODE(n->handle);
	i++;

	return handle|(i>0xFFF ? 0xFFF : i);
}

static const struct nla_policy u32_policy[TCA_U32_MAX + 1] = {
	[TCA_U32_CLASSID]	= { .type = NLA_U32 },
	[TCA_U32_HASH]		= { .type = NLA_U32 },
	[TCA_U32_LINK]		= { .type = NLA_U32 },
	[TCA_U32_DIVISOR]	= { .type = NLA_U32 },
	[TCA_U32_SEL]		= { .len = sizeof(struct tc_u32_sel) },
	[TCA_U32_INDEV]		= { .type = NLA_STRING, .len = IFNAMSIZ },
	[TCA_U32_MARK]		= { .len = sizeof(struct tc_u32_mark) },
};

static int u32_set_parms(struct tcf_proto *tp, unsigned long base,
			 struct tc_u_hnode *ht,
			 struct tc_u_knode *n, struct nlattr **tb,
			 struct nlattr *est)
{
	int err;
	struct tcf_exts e;

	err = tcf_exts_validate(tp, tb, est, &e, &u32_ext_map);
	if (err < 0)
		return err;

	err = -EINVAL;
	if (tb[TCA_U32_LINK]) {
		u32 handle = nla_get_u32(tb[TCA_U32_LINK]);
		struct tc_u_hnode *ht_down = NULL, *ht_old;

		if (TC_U32_KEY(handle))
			goto errout;

		if (handle) {
			ht_down = u32_lookup_ht(ht->tp_c, handle);

			if (ht_down == NULL)
				goto errout;
			ht_down->refcnt++;
		}

		tcf_tree_lock(tp);
		ht_old = n->ht_down;
		n->ht_down = ht_down;
		tcf_tree_unlock(tp);

		if (ht_old)
			ht_old->refcnt--;
	}
	if (tb[TCA_U32_CLASSID]) {
	//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4
		n->res.classid = nla_get_u32(tb[TCA_U32_CLASSID]); //把应用层过来的flowid 22:4中的flowid赋值给res
		tcf_bind_filter(tp, &n->res, base);
	}

#ifdef CONFIG_NET_CLS_IND
	if (tb[TCA_U32_INDEV]) {
		err = tcf_change_indev(tp, n->indev, tb[TCA_U32_INDEV]);
		if (err < 0)
			goto errout;
	}
#endif
	tcf_exts_change(tp, &n->exts, &e);

	return 0;
errout:
	tcf_exts_destroy(tp, &e);
	return err;
}

//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4
////tp为新创建或者需要修改的tc filter过滤器tcf_proto， base为flowid 22:4对应的htb_class结构，见htb_get. tca为应用层下来的参数信息，handle为内核为该tc filter自动生成的handle
static int u32_change(struct tcf_proto *tp, unsigned long base, u32 handle,
		      struct nlattr **tca,
		      unsigned long *arg)
{
	struct tc_u_common *tp_c = tp->data;
	struct tc_u_hnode *ht;
	struct tc_u_knode *n;
	struct tc_u32_sel *s;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_U32_MAX + 1];
	u32 htid;
	int err;

	if (opt == NULL)
		return handle ? -EINVAL : 0;

	err = nla_parse_nested(tb, TCA_U32_MAX, opt, u32_policy);
	if (err < 0)
		return err;

	if ((n = (struct tc_u_knode*)*arg) != NULL) {
		if (TC_U32_KEY(n->handle) == 0)
			return -EINVAL;

		return u32_set_parms(tp, base, n->ht_up, n, tb, tca[TCA_RATE]);
	}

	if (tb[TCA_U32_DIVISOR]) {
		unsigned divisor = nla_get_u32(tb[TCA_U32_DIVISOR]);

		if (--divisor > 0x100)
			return -EINVAL;
		if (TC_U32_KEY(handle))
			return -EINVAL;
		if (handle == 0) {
			handle = gen_new_htid(tp->data);
			if (handle == 0)
				return -ENOMEM;
		}
		ht = kzalloc(sizeof(*ht) + divisor*sizeof(void*), GFP_KERNEL);
		if (ht == NULL)
			return -ENOBUFS;
		ht->tp_c = tp_c;
		ht->refcnt = 1;
		ht->divisor = divisor;
		ht->handle = handle;
		ht->prio = tp->prio;
		ht->next = tp_c->hlist;
		tp_c->hlist = ht;
		*arg = (unsigned long)ht;
		return 0;
	}

	if (tb[TCA_U32_HASH]) {
		htid = nla_get_u32(tb[TCA_U32_HASH]);
		if (TC_U32_HTID(htid) == TC_U32_ROOT) {
			ht = tp->root;
			htid = ht->handle;
		} else {
			ht = u32_lookup_ht(tp->data, TC_U32_HTID(htid));
			if (ht == NULL)
				return -EINVAL;
		}
	} else {
		ht = tp->root;
		htid = ht->handle;
	}

	if (ht->divisor < TC_U32_HASH(htid))
		return -EINVAL;

	if (handle) {
		if (TC_U32_HTID(handle) && TC_U32_HTID(handle^htid))
			return -EINVAL;
		handle = htid | TC_U32_NODE(handle);
	} else
		handle = gen_new_kid(ht, htid);

	if (tb[TCA_U32_SEL] == NULL)
		return -EINVAL;

	s = nla_data(tb[TCA_U32_SEL]);

	n = kzalloc(sizeof(*n) + s->nkeys*sizeof(struct tc_u32_key), GFP_KERNEL);
	if (n == NULL)
		return -ENOBUFS;

#ifdef CONFIG_CLS_U32_PERF
	n->pf = kzalloc(sizeof(struct tc_u32_pcnt) + s->nkeys*sizeof(u64), GFP_KERNEL);
	if (n->pf == NULL) {
		kfree(n);
		return -ENOBUFS;
	}
#endif

	memcpy(&n->sel, s, sizeof(*s) + s->nkeys*sizeof(struct tc_u32_key));
	n->ht_up = ht;
	n->handle = handle;
	n->fshift = s->hmask ? ffs(ntohl(s->hmask)) - 1 : 0;

#ifdef CONFIG_CLS_U32_MARK
	if (tb[TCA_U32_MARK]) {
		struct tc_u32_mark *mark;

		mark = nla_data(tb[TCA_U32_MARK]);
		memcpy(&n->mark, mark, sizeof(struct tc_u32_mark));
		n->mark.success = 0;
	}
#endif

	err = u32_set_parms(tp, base, ht, n, tb, tca[TCA_RATE]);
	if (err == 0) {
		struct tc_u_knode **ins;
		for (ins = &ht->ht[TC_U32_HASH(handle)]; *ins; ins = &(*ins)->next)
			if (TC_U32_NODE(handle) < TC_U32_NODE((*ins)->handle))
				break;

		n->next = *ins;
		tcf_tree_lock(tp);
		*ins = n;
		tcf_tree_unlock(tp);

		*arg = (unsigned long)n;
		return 0;
	}
#ifdef CONFIG_CLS_U32_PERF
	kfree(n->pf);
#endif
	kfree(n);
	return err;
}

static void u32_walk(struct tcf_proto *tp, struct tcf_walker *arg)
{
	struct tc_u_common *tp_c = tp->data;
	struct tc_u_hnode *ht;
	struct tc_u_knode *n;
	unsigned h;

	if (arg->stop)
		return;

	for (ht = tp_c->hlist; ht; ht = ht->next) {
		if (ht->prio != tp->prio)
			continue;
		if (arg->count >= arg->skip) {
			if (arg->fn(tp, (unsigned long)ht, arg) < 0) {
				arg->stop = 1;
				return;
			}
		}
		arg->count++;
		for (h = 0; h <= ht->divisor; h++) {
			for (n = ht->ht[h]; n; n = n->next) {
				if (arg->count < arg->skip) {
					arg->count++;
					continue;
				}
				if (arg->fn(tp, (unsigned long)n, arg) < 0) {
					arg->stop = 1;
					return;
				}
				arg->count++;
			}
		}
	}
}

static int u32_dump(struct tcf_proto *tp, unsigned long fh,
		     struct sk_buff *skb, struct tcmsg *t)
{
	struct tc_u_knode *n = (struct tc_u_knode*)fh;
	struct nlattr *nest;

	if (n == NULL)
		return skb->len;

	t->tcm_handle = n->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	if (TC_U32_KEY(n->handle) == 0) {
		struct tc_u_hnode *ht = (struct tc_u_hnode*)fh;
		u32 divisor = ht->divisor+1;
		NLA_PUT_U32(skb, TCA_U32_DIVISOR, divisor);
	} else {
		NLA_PUT(skb, TCA_U32_SEL,
			sizeof(n->sel) + n->sel.nkeys*sizeof(struct tc_u32_key),
			&n->sel);
		if (n->ht_up) {
			u32 htid = n->handle & 0xFFFFF000;
			NLA_PUT_U32(skb, TCA_U32_HASH, htid);
		}
		if (n->res.classid)
			NLA_PUT_U32(skb, TCA_U32_CLASSID, n->res.classid);
		if (n->ht_down)
			NLA_PUT_U32(skb, TCA_U32_LINK, n->ht_down->handle);

#ifdef CONFIG_CLS_U32_MARK
		if (n->mark.val || n->mark.mask)
			NLA_PUT(skb, TCA_U32_MARK, sizeof(n->mark), &n->mark);
#endif

		if (tcf_exts_dump(skb, &n->exts, &u32_ext_map) < 0)
			goto nla_put_failure;

#ifdef CONFIG_NET_CLS_IND
		if(strlen(n->indev))
			NLA_PUT_STRING(skb, TCA_U32_INDEV, n->indev);
#endif
#ifdef CONFIG_CLS_U32_PERF
		NLA_PUT(skb, TCA_U32_PCNT,
		sizeof(struct tc_u32_pcnt) + n->sel.nkeys*sizeof(u64),
			n->pf);
#endif
	}

	nla_nest_end(skb, nest);

	if (TC_U32_KEY(n->handle))
		if (tcf_exts_dump_stats(skb, &n->exts, &u32_ext_map) < 0)
			goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

//图形化理解参考参考TC流量控制实现分析(初步)*/   //详细理解也可以参考<<LINUX高级路由和流量控制>>
//tcf_proto里面的ops指向这里  tc filter u32过滤器的结构,起源结构在tcf_proto
//主要有cls_u32_ops cls_basic_ops  cls_cgroup_ops  cls_flow_ops cls_route4_ops RSVP_OPS
static struct tcf_proto_ops cls_u32_ops ;//__read_mostly = {
	.kind		=	"u32",
	.classify	=	u32_classify,
	.init		=	u32_init, //tc_ctl_tclass调用
	.destroy	=	u32_destroy,

	//讲一个过滤器元素的句柄映射到一个内部过滤器标识符，实际上是过滤器实例指针，并将其返回
	.get		=	u32_get, //通过tcmsg -> tcm_handle 就能找到对应的tcf_proto过滤器的跟信息tc_u_hnode
	.put		=	u32_put,
	.change		=	u32_change,
	.delete		=	u32_delete,
	.walk		=	u32_walk,
	.dump		=	u32_dump,
	.owner		=	THIS_MODULE,
};

static int __init init_u32(void)
{
	pr_info("u32 classifier\n");
#ifdef CONFIG_CLS_U32_PERF
	pr_info("    Performance counters on\n");
#endif
#ifdef CONFIG_NET_CLS_IND
	pr_info("    input device check on\n");
#endif
#ifdef CONFIG_NET_CLS_ACT
	pr_info("    Actions configured\n");
#endif
	return register_tcf_proto_ops(&cls_u32_ops);
}

static void __exit exit_u32(void)
{
	unregister_tcf_proto_ops(&cls_u32_ops);
}

module_init(init_u32)
module_exit(exit_u32)
MODULE_LICENSE("GPL");

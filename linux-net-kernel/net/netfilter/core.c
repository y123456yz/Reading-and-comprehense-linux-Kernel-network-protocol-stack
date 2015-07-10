/* netfilter.c: look after the filters for various protocols.
 * Heavily influenced by the old firewall.c by David Bonn and Alan Cox.
 *
 * Thanks to Rob `CmdrTaco' Malda for not influencing this code in any
 * way.
 *
 * Rusty Russell (C)2000 -- This code is GPL.
 */
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <net/protocol.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "nf_internals.h"

static DEFINE_MUTEX(afinfo_mutex);

//const struct nf_afinfo *nf_afinfo[NFPROTO_NUMPROTO] __read_mostly;
const struct nf_afinfo *nf_afinfo[NFPROTO_NUMPROTO]; //目前被nf_queue功能使用，通过nf_register_afinfo注册 IPV4见nf_ip_afinfo
EXPORT_SYMBOL(nf_afinfo);

int nf_register_afinfo(const struct nf_afinfo *afinfo)
{
	int err;

	err = mutex_lock_interruptible(&afinfo_mutex);
	if (err < 0)
		return err;
	rcu_assign_pointer(nf_afinfo[afinfo->family], afinfo);
	mutex_unlock(&afinfo_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(nf_register_afinfo);

void nf_unregister_afinfo(const struct nf_afinfo *afinfo)
{
	mutex_lock(&afinfo_mutex);
	rcu_assign_pointer(nf_afinfo[afinfo->family], NULL);
	mutex_unlock(&afinfo_mutex);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nf_unregister_afinfo);

/*
这是一个三维的实现模型，第一维可以认为是不同的网络协议簇，第二维是协议簇中事件(对应一些检测位置)，第三维就是这个链表中可以挂载的
所有检测函数，数组nf_hooks的每个元素只是一个链表头位置，它下面可以挂接任意多的检测函数，从而形成一个动态挂载任意多的检测。
该数组中的每一个队列中挂接的是一个struct nf_hook_ops

struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS]是其中核心的数据结构。nf_hooks的功能类似一个二维的函数指针数组。
nf_hooks数组的第一维是按照协议进行分类的，对于不同的协议有不同的hook点和hook函数，常见的协议包括ipv4，ipv6，arp，bridge等。
nf_hooks数组的第二维是按照hook点进行划分的，分为
NF_INET_PRE_ROUTING，NF_INET_LOCAL_IN，NF_INET_FORWARD，NF_INET_LOCAL_OUT，NF_INET_POST_ROUTING等5个hook点，与iptables的5个链相对应。
nf_hooks数组中的每一个元素可以理解为一个函数指针链表的链表头。这个函数指针链表是一个有序链表，按照函数hook的优先级进行排序
参考地址:http://www.360doc.com/content/13/0914/12/3884271_314370861.shtml
*/
struct list_head nf_hooks[NFPROTO_NUMPROTO][NF_MAX_HOOKS] __read_mostly;
EXPORT_SYMBOL(nf_hooks);
static DEFINE_MUTEX(nf_hook_mutex);

int nf_register_hook(struct nf_hook_ops *reg)
{
	struct nf_hook_ops *elem;
	int err;

	err = mutex_lock_interruptible(&nf_hook_mutex);
	if (err < 0)
		return err;
	list_for_each_entry(elem, &nf_hooks[reg->pf][reg->hooknum], list) {
		if (reg->priority < elem->priority)
			break;
	}
	list_add_rcu(&reg->list, elem->list.prev); //yang add 把reg按照优先级加入链表中去
	mutex_unlock(&nf_hook_mutex);
	return 0;
}
EXPORT_SYMBOL(nf_register_hook);

void nf_unregister_hook(struct nf_hook_ops *reg)
{
	mutex_lock(&nf_hook_mutex);
	list_del_rcu(&reg->list);
	mutex_unlock(&nf_hook_mutex);

	synchronize_net();
}
EXPORT_SYMBOL(nf_unregister_hook);

//yang add 按照[reg->pf][reg->hooknum]加入到nf_hooks对应的链表中去
int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;
	int err = 0;

	for (i = 0; i < n; i++) {
		err = nf_register_hook(&reg[i]);
		if (err)
			goto err;
	}
	return err;

err:
	if (i > 0)
		nf_unregister_hooks(reg, i);
	return err;
}
EXPORT_SYMBOL(nf_register_hooks);

void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		nf_unregister_hook(&reg[i]);
}
EXPORT_SYMBOL(nf_unregister_hooks);

//遍历hook函数，//如果执行hook函数返回值不是ACCPT活着REPEAT的时候，则从hook链表中直接返回不会在继续执行next hook函数，参考nf_hook_slow
unsigned int nf_iterate(struct list_head *head,
			struct sk_buff *skb,
			unsigned int hook,
			const struct net_device *indev,
			const struct net_device *outdev,
			struct list_head **i,
			int (*okfn)(struct sk_buff *),
			int hook_thresh)
{
	unsigned int verdict;

	/*
	 * The caller must not block between calls to this
	 * function because of risk of continuing from deleted element.
	 */
	list_for_each_continue_rcu(*i, head) {//遍历i链表
		struct nf_hook_ops *elem = (struct nf_hook_ops *)*i;

		if (hook_thresh > elem->priority)
			continue;

		/* Optimization: we don't need to hold module
		   reference here, since function can't sleep. --RR */
		verdict = elem->hook(hook, skb, indev, outdev, okfn);
		if (verdict != NF_ACCEPT) {//如果当前hook函数的返回值为ACCEPT,则继续下一个hook继续  hook函数在函数nf_register_hooks中注册
#ifdef CONFIG_NETFILTER_DEBUG
			if (unlikely((verdict & NF_VERDICT_MASK)
							> NF_MAX_VERDICT)) {
				NFDEBUG("Evil return from %p(%u).\n",
					elem->hook, hook);
				continue;
			}
#endif
			if (verdict != NF_REPEAT)
				return verdict;
			*i = (*i)->prev;//如果verdict值为NF_REPEAT则继续执行该HOOK函数，这里注意，可能会出现死循环
		}
	}
	return NF_ACCEPT;
}


/* Returns 1 if okfn() needs to be executed by the caller,
 * -EPERM for NF_DROP, 0 otherwise. 
 nf_hook_slow去完成钩子函数okfn的顺序遍历(优先级从小到大依次执行)。
 */
int nf_hook_slow(u_int8_t pf, unsigned int hook, struct sk_buff *skb,
		 struct net_device *indev,
		 struct net_device *outdev,
		 int (*okfn)(struct sk_buff *),
		 int hook_thresh)
{
	struct list_head *elem;
	unsigned int verdict;
	int ret = 0;

	/* We may already have this, but read-locks nest anyway */
	rcu_read_lock();

	elem = &nf_hooks[pf][hook];
next_hook:
	verdict = nf_iterate(&nf_hooks[pf][hook], skb, hook, indev,
			     outdev, &elem, okfn, hook_thresh);
	if (verdict == NF_ACCEPT || verdict == NF_STOP) {
		ret = 1;
	} else if (verdict == NF_DROP) {
		kfree_skb(skb);
		ret = -EPERM;
	} else if ((verdict & NF_VERDICT_MASK) == NF_QUEUE) {
		if (!nf_queue(skb, elem, pf, hook, indev, outdev, okfn,
			      verdict >> NF_VERDICT_BITS))
			goto next_hook;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(nf_hook_slow);


int skb_make_writable(struct sk_buff *skb, unsigned int writable_len)
{
	if (writable_len > skb->len)
		return 0;

	/* Not exclusive use of packet?  Must copy. */
	if (!skb_cloned(skb)) {
		if (writable_len <= skb_headlen(skb))
			return 1;
	} else if (skb_clone_writable(skb, writable_len))
		return 1;

	if (writable_len <= skb_headlen(skb))
		writable_len = 0;
	else
		writable_len -= skb_headlen(skb);

	return !!__pskb_pull_tail(skb, writable_len);
}
EXPORT_SYMBOL(skb_make_writable);

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
/* This does not belong here, but locally generated errors need it if connection
   tracking in use: without this, connection may not be in hash table, and hence
   manufactured ICMP or RST packets will not be associated with it. */
void (*ip_ct_attach)(struct sk_buff *, struct sk_buff *);//指向nf_conntrack_attach， 见nf_conntrack_init
EXPORT_SYMBOL(ip_ct_attach);

void nf_ct_attach(struct sk_buff *new, struct sk_buff *skb)
{
	void (*attach)(struct sk_buff *, struct sk_buff *);

	if (skb->nfct) {
		rcu_read_lock();
		attach = rcu_dereference(ip_ct_attach);
		if (attach)
			attach(new, skb);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(nf_ct_attach);

void (*nf_ct_destroy)(struct nf_conntrack *);//指向destroy_conntrack，见nf_conntrack_init 
EXPORT_SYMBOL(nf_ct_destroy);

void nf_conntrack_destroy(struct nf_conntrack *nfct)
{
	void (*destroy)(struct nf_conntrack *);

	rcu_read_lock();
	destroy = rcu_dereference(nf_ct_destroy);
	BUG_ON(destroy == NULL);
	destroy(nfct);
	rcu_read_unlock();
}
EXPORT_SYMBOL(nf_conntrack_destroy);
#endif /* CONFIG_NF_CONNTRACK */

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *proc_net_netfilter;
EXPORT_SYMBOL(proc_net_netfilter);
#endif

void __init netfilter_init(void)
{
	int i, h;
	for (i = 0; i < ARRAY_SIZE(nf_hooks); i++) {
		for (h = 0; h < NF_MAX_HOOKS; h++)
			INIT_LIST_HEAD(&nf_hooks[i][h]);
	}

#ifdef CONFIG_PROC_FS
	proc_net_netfilter = proc_mkdir("netfilter", init_net.proc_net);
	if (!proc_net_netfilter)
		panic("cannot create netfilter proc entry");
#endif

	if (netfilter_queue_init() < 0)
		panic("cannot initialize nf_queue");
	if (netfilter_log_init() < 0)
		panic("cannot initialize nf_log");
}

#ifdef CONFIG_SYSCTL
struct ctl_path nf_net_netfilter_sysctl_path[] = {
	{ .procname = "net", },
	{ .procname = "netfilter", },
	{ }
};
EXPORT_SYMBOL_GPL(nf_net_netfilter_sysctl_path);
#endif /* CONFIG_SYSCTL */

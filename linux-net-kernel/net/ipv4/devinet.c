/*
 *	NET3	IP device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Derived from the IP parts of dev.c 1.0.19
 * 		Authors:	Ross Biro
 *				Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *				Mark Evans, <evansmp@uhura.aston.ac.uk>
 *
 *	Additional Authors:
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *	Changes:
 *		Alexey Kuznetsov:	pa_* fields are replaced with ifaddr
 *					lists.
 *		Cyrus Durgin:		updated for kmod
 *		Matthias Andree:	in devinet_ioctl, compare label and
 *					address (4.4BSD alias style support),
 *					fall back to comparing just the label
 *					if no match found.
 */


#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/slab.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif
#include <linux/kmod.h>

#include <net/arp.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ip_fib.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>

static struct ipv4_devconf ipv4_devconf = {
	.data = {
		[IPV4_DEVCONF_ACCEPT_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SEND_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SECURE_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SHARED_MEDIA - 1] = 1,
	},
};

static struct ipv4_devconf ipv4_devconf_dflt = {
	.data = {
		[IPV4_DEVCONF_ACCEPT_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SEND_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SECURE_REDIRECTS - 1] = 1,
		[IPV4_DEVCONF_SHARED_MEDIA - 1] = 1,
		[IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE - 1] = 1,
	},
};

#define IPV4_DEVCONF_DFLT(net, attr) \
	IPV4_DEVCONF((*net->ipv4.devconf_dflt), attr)

static const struct nla_policy ifa_ipv4_policy[IFA_MAX+1] = {
	[IFA_LOCAL]     	= { .type = NLA_U32 },
	[IFA_ADDRESS]   	= { .type = NLA_U32 },
	[IFA_BROADCAST] 	= { .type = NLA_U32 },
	[IFA_LABEL]     	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
};

static void rtmsg_ifa(int event, struct in_ifaddr *, struct nlmsghdr *, u32);

//http://www.linuxidc.com/Linux/2013-07/86999.htm如图 1中所示，
//Linux的网络子系统一共有3个通知链：表示ipv4地址发生变化时的inetaddr_chain；
//表示ipv6地址发生变化的inet6addr_chain；还有表示设备注册、状态变化的netdev_chain。
//static BLOCKING_NOTIFIER_HEAD(inetaddr_chain);
/*  
原子通知链（ Atomic notifier chains ）：通知链元素的回调函数（当事件发生时要执行的函数）在中断或原子操作上下文中运行，不允许阻塞。对应的链表头结构：
可阻塞通知链（ Blocking notifier chains ）：通知链元素的回调函数在进程上下文中运行，允许阻塞。对应的链表头：
原始通知链（ Raw notifierchains ）：对通知链元素的回调函数没有任何限制，所有锁和保护机制都由调用者维护。对应的链表头：
SRCU 通知链（ SRCU notifier chains ）：可阻塞通知链的一种变体。对应的链表头：

register_inetaddr_notifier和unregister_inetaddr_notifier配对
*/
struct blocking_notifier_head inetaddr_chain = BLOCKING_NOTIFIER_INIT(inetaddr_chain) 

static void inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy);
#ifdef CONFIG_SYSCTL
static void devinet_sysctl_register(struct in_device *idev);
static void devinet_sysctl_unregister(struct in_device *idev);
#else
static inline void devinet_sysctl_register(struct in_device *idev)
{
}
static inline void devinet_sysctl_unregister(struct in_device *idev)
{
}
#endif

/* Locks all the inet devices. */

static struct in_ifaddr *inet_alloc_ifa(void)
{
	return kzalloc(sizeof(struct in_ifaddr), GFP_KERNEL);
}

static void inet_rcu_free_ifa(struct rcu_head *head)
{
	struct in_ifaddr *ifa = container_of(head, struct in_ifaddr, rcu_head);
	if (ifa->ifa_dev)
		in_dev_put(ifa->ifa_dev);
	kfree(ifa);
}

static inline void inet_free_ifa(struct in_ifaddr *ifa)
{
	call_rcu(&ifa->rcu_head, inet_rcu_free_ifa);
}

void in_dev_finish_destroy(struct in_device *idev)
{
	struct net_device *dev = idev->dev;

	WARN_ON(idev->ifa_list);
	WARN_ON(idev->mc_list);
#ifdef NET_REFCNT_DEBUG
	printk(KERN_DEBUG "in_dev_finish_destroy: %p=%s\n",
	       idev, dev ? dev->name : "NIL");
#endif
	dev_put(dev);
	if (!idev->dead)
		pr_err("Freeing alive in_device %p\n", idev);
	else
		kfree(idev);
}
EXPORT_SYMBOL(in_dev_finish_destroy);

/*
  * inetdev_init()为通过参数指定的网络设备分配并绑定
  * IP配置块。
  */
static struct in_device *inetdev_init(struct net_device *dev)
{
	struct in_device *in_dev;

	ASSERT_RTNL();

	/*
	  * 分配一个IP配置块
	  */
	in_dev = kzalloc(sizeof(*in_dev), GFP_KERNEL);
	if (!in_dev)
		goto out;
	/*
	  * 初始化IP配置块中的一些成员，包括
	  * IPv4配置的默认值，以及所属的网络设备。
	  */
	memcpy(&in_dev->cnf, dev_net(dev)->ipv4.devconf_dflt,
			sizeof(in_dev->cnf));
	in_dev->cnf.sysctl = NULL;
	in_dev->dev = dev;
	/*
	  * 为IP配置块分配邻居协议参数配置块，
	  * 并根据ARP表初始化
	  */
	if ((in_dev->arp_parms = neigh_parms_alloc(dev, &arp_tbl)) == NULL)
		goto out_kfree;
	if (IPV4_DEVCONF(in_dev->cnf, FORWARDING))
		dev_disable_lro(dev);
	/* Reference in_dev->dev */
	dev_hold(dev);
	/* Account for reference dev->ip_ptr (below) */
	in_dev_hold(in_dev);

	devinet_sysctl_register(in_dev);
	/*
	  * 初始化IGMP模块
	  */
	ip_mc_init_dev(in_dev);
	/*
	  * 如果网络设备已启用，则初始化该网络
	  * 设备上的组播消息，例如，将
	  * 该网络设备加入到224.0.0.1组播组等操作
	  */
	if (dev->flags & IFF_UP)
		ip_mc_up(in_dev);

	/* we can receive as soon as ip_ptr is set -- do this last */
	rcu_assign_pointer(dev->ip_ptr, in_dev);
/*
  * 操作成功，返回分配并绑定成功的IP配置块，
  * 否则返回NULL。
  */
out:
	return in_dev;
out_kfree:
	kfree(in_dev);
	in_dev = NULL;
	goto out;
}

static void in_dev_rcu_put(struct rcu_head *head)
{
	struct in_device *idev = container_of(head, struct in_device, rcu_head);
	in_dev_put(idev);
}

/*
  * inetdev_destroy()通常在设备注销时被调用，
  * 释放指定的IP配置块。
  */
static void inetdev_destroy(struct in_device *in_dev)
{
	struct in_ifaddr *ifa;
	struct net_device *dev;

	ASSERT_RTNL();

	dev = in_dev->dev;

	/*
	  * 标识带释放的IP配置块正处在释放过程中。
	  */
	in_dev->dead = 1;

	/*
	  * 销毁组播相关的配置，如停止相关定时器。
	  */
	ip_mc_destroy_dev(in_dev);

	/*
	  * 删除并释放所有的IP地址块。
	  */
	while ((ifa = in_dev->ifa_list) != NULL) {
		inet_del_ifa(in_dev, &in_dev->ifa_list, 0);
		inet_free_ifa(ifa);
	}

	/*
	  * 将网络设备指向IP配置块的指针设置为NULL。
	  */
	dev->ip_ptr = NULL;

	/*
	  * 注销邻居子系统相关的配置参数
	  */
	devinet_sysctl_unregister(in_dev);
	/*
	  * 释放IP配置块中的邻居协议参数配置块。
	  */
	neigh_parms_release(&arp_tbl, in_dev->arp_parms);
	arp_ifdown(dev);

	/*
	  * 通过RCU机制释放IP配置块。
	  */
	call_rcu(&in_dev->rcu_head, in_dev_rcu_put);
}

/*
  * 根据指定网络设备的IP配置块，检查两个给定的
  * IP地址是否同属于一个子网
  */
int inet_addr_onlink(struct in_device *in_dev, __be32 a, __be32 b)
{
	rcu_read_lock();
	for_primary_ifa(in_dev) {
		if (inet_ifa_match(a, ifa)) {
			if (!b || inet_ifa_match(b, ifa)) {
				rcu_read_unlock();
				return 1;
			}
		}
	} endfor_ifa(in_dev);
	rcu_read_unlock();
	return 0;
}

static void __inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy, struct nlmsghdr *nlh, u32 pid)
{
	struct in_ifaddr *promote = NULL;
	struct in_ifaddr *ifa, *ifa1 = *ifap;
	struct in_ifaddr *last_prim = in_dev->ifa_list;
	struct in_ifaddr *prev_prom = NULL;
	int do_promote = IN_DEV_PROMOTE_SECONDARIES(in_dev);

	ASSERT_RTNL();

	/* 1. Deleting primary ifaddr forces deletion all secondaries
	 * unless alias promotion is set
	 **/

	/*
	  * 如果删除的是主IP地址，则需对从属
	  * IP地址作相应的处理。如果没有启用
	  * promote_secondaries，则删除所有该主IP地址的
	  * 从属IP地址，否则选择一个从属IP地址，
	  * 升级为主IP地址。
	  */
	if (!(ifa1->ifa_flags & IFA_F_SECONDARY)) {
		struct in_ifaddr **ifap1 = &ifa1->ifa_next;

		while ((ifa = *ifap1) != NULL) {
			if (!(ifa->ifa_flags & IFA_F_SECONDARY) &&
			    ifa1->ifa_scope <= ifa->ifa_scope)
				last_prim = ifa;

			if (!(ifa->ifa_flags & IFA_F_SECONDARY) ||
			    ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa)) {
				ifap1 = &ifa->ifa_next;
				prev_prom = ifa;
				continue;
			}

			if (!do_promote) {
				*ifap1 = ifa->ifa_next;

				rtmsg_ifa(RTM_DELADDR, ifa, nlh, pid);
				blocking_notifier_call_chain(&inetaddr_chain,
						NETDEV_DOWN, ifa);
				inet_free_ifa(ifa);
			} else {
				promote = ifa;
				break;
			}
		}
	}

	/* 2. Unlink it */

	/*
	  * 先将待删除的IP地址块从链表中删除，
	  * 后续操作中再根据destroy作处理
	  */
	*ifap = ifa1->ifa_next;

	/* 3. Announce address deletion */

	/* Send message first, then call notifier.
	   At first sight, FIB update triggered by notifier
	   will refer to already deleted ifaddr, that could confuse
	   netlink listeners. It is not true: look, gated sees
	   that route deleted and if it still thinks that ifaddr
	   is valid, it will try to restore deleted routes... Grr.
	   So that, this order is correct.
	 */
	/*
	  * 通过netlink发送RTM_DELADDR消息给感兴趣的
	  * 用户进程
	  */
	rtmsg_ifa(RTM_DELADDR, ifa1, nlh, pid);
	/*
	  * 通过inetaddr_chain通知链发送删除IP地址事件
	  * 和IP地址信息给感兴趣的其他内核模块
	  */
	blocking_notifier_call_chain(&inetaddr_chain, NETDEV_DOWN, ifa1);

	/*
	  * 如果启用了promote_secondaries，将选择到的
	  * 从属IP地址升级为主IP地址，发送从属
	  * IP地址升级为主IP地址消息。并通过
	  * fib_add_ifaddr()将从属IP地址相关的路由
	  * 表项添加到ip_fib_local_table路由表中。
	  */
	if (promote) {

		if (prev_prom) {
			prev_prom->ifa_next = promote->ifa_next;
			promote->ifa_next = last_prim->ifa_next;
			last_prim->ifa_next = promote;
		}

		promote->ifa_flags &= ~IFA_F_SECONDARY;
		rtmsg_ifa(RTM_NEWADDR, promote, nlh, pid);
		blocking_notifier_call_chain(&inetaddr_chain,
				NETDEV_UP, promote);
		for (ifa = promote->ifa_next; ifa; ifa = ifa->ifa_next) {
			if (ifa1->ifa_mask != ifa->ifa_mask ||
			    !inet_ifa_match(ifa1->ifa_address, ifa))
					continue;
			fib_add_ifaddr(ifa);
		}

	}
	
	/*
	  * 如果根据destroy需要释放，则通过RCU机制
	  * 释放IP配置块。在删除掉最后一个地址后，
	  * 释放所有的IP配置块。
	  */
	if (destroy)
		inet_free_ifa(ifa1);
}

static void inet_del_ifa(struct in_device *in_dev, struct in_ifaddr **ifap,
			 int destroy)
{
	__inet_del_ifa(in_dev, ifap, destroy, NULL, 0);
}

static int __inet_insert_ifa(struct in_ifaddr *ifa, struct nlmsghdr *nlh,
			     u32 pid)
{
	struct in_device *in_dev = ifa->ifa_dev;
	struct in_ifaddr *ifa1, **ifap, **last_primary;

	ASSERT_RTNL();

	if (!ifa->ifa_local) {
		inet_free_ifa(ifa);
		return 0;
	}

	/*
	  * 先清除地址的从属标志，因为配置的地址
	  * 是主IP地址还是从属IP地址，并非根据标志
	  * 而是根据当前已配置的IP地址
	  */
	ifa->ifa_flags &= ~IFA_F_SECONDARY;
	last_primary = &in_dev->ifa_list;

	/*
	  * 在所有主IP地址中查找，如果存在相同
	  * 寻址范围的地址，则本次添加的IP地址
	  * 为从属IP地址。而如果已配置了相同的
	  * 地址，则返回错误码-EEXIST。
	  */
	for (ifap = &in_dev->ifa_list; (ifa1 = *ifap) != NULL;
	     ifap = &ifa1->ifa_next) {
		if (!(ifa1->ifa_flags & IFA_F_SECONDARY) &&
		    ifa->ifa_scope <= ifa1->ifa_scope)
			last_primary = &ifa1->ifa_next;
		if (ifa1->ifa_mask == ifa->ifa_mask &&
		    inet_ifa_match(ifa1->ifa_address, ifa)) {
			if (ifa1->ifa_local == ifa->ifa_local) {
				inet_free_ifa(ifa);
				return -EEXIST;
			}
			if (ifa1->ifa_scope != ifa->ifa_scope) {
				inet_free_ifa(ifa);
				return -EINVAL;
			}
			ifa->ifa_flags |= IFA_F_SECONDARY;
		}
	}

	/*
	  * 如果配置的是第一个地址，则先添加
	  * 熵到伪随机数引擎中，然后将其地址
	  * 添加到IP配置块中。
	  */
	if (!(ifa->ifa_flags & IFA_F_SECONDARY)) {
		net_srandom(ifa->ifa_local);
		ifap = last_primary;
	}

	ifa->ifa_next = *ifap;
	*ifap = ifa;

	/* Send message first, then call notifier.
	   Notifier will trigger FIB update, so that
	   listeners of netlink will know about new ifaddr */
	/*
	  * 通过netlink发送RTM_NEWADDR消息给感兴趣的
	  * 用户进程。
	  */
	rtmsg_ifa(RTM_NEWADDR, ifa, nlh, pid);
	/*
	  * 通过inetaddr_chain通知链发送添加IP地址事件
	  * 和IP地址消息给感兴趣的其他内核模块。
	  */
	blocking_notifier_call_chain(&inetaddr_chain, NETDEV_UP, ifa);

	return 0;
}

/*
  * inet_insert_ifa()用来添加一个IP地址。
  * 通常在设置广播地址、点对点对端
  * 地址和地址掩码时，先调用inet_del_ifa()清除
  * 原有的信息，然后再调用inet_insert_ifa()进行
  * 设置
  */
static int inet_insert_ifa(struct in_ifaddr *ifa)
{
	return __inet_insert_ifa(ifa, NULL, 0);
}

static int inet_set_ifa(struct net_device *dev, struct in_ifaddr *ifa)
{
	struct in_device *in_dev = __in_dev_get_rtnl(dev);

	ASSERT_RTNL();

	if (!in_dev) {
		inet_free_ifa(ifa);
		return -ENOBUFS;
	}
	ipv4_devconf_setall(in_dev);
	if (ifa->ifa_dev != in_dev) {
		WARN_ON(ifa->ifa_dev);
		in_dev_hold(in_dev);
		ifa->ifa_dev = in_dev;
	}
	if (ipv4_is_loopback(ifa->ifa_local))
		ifa->ifa_scope = RT_SCOPE_HOST;
	return inet_insert_ifa(ifa);
}

/*
  * inetdev_by_index()根据网络设备索引号获取
  * 对应网络设备的IP配置块
  */
struct in_device *inetdev_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;
	struct in_device *in_dev = NULL;
	read_lock(&dev_base_lock);
	/*
	  * 根据索引获取对应的网络设备
	  */
	dev = __dev_get_by_index(net, ifindex);
	/*
	  * 如果获得的网络设备有效，则返回其
	  * IP配置块，否则返回NULL。
	  */
	if (dev)
		in_dev = in_dev_get(dev);
	read_unlock(&dev_base_lock);
	return in_dev;
}

EXPORT_SYMBOL(inetdev_by_index);

/* Called only from RTNL semaphored context. No locks. */
/*
  * inet_ifa_byprefix()在正在配置的输入设备的主IP
  * 地址中查找与前缀和掩码匹配的IP地址
  */
struct in_ifaddr *inet_ifa_byprefix(struct in_device *in_dev, __be32 prefix,
				    __be32 mask)
{
	ASSERT_RTNL();

	for_primary_ifa(in_dev) {
		if (ifa->ifa_mask == mask && inet_ifa_match(prefix, ifa))
			return ifa;
	} endfor_ifa(in_dev);
	return NULL;
}

/*
  * 当通过netlink，操作类型为RTM_DELADDR删除IP地址时，
  * 才调用此函数
  */
static int inet_rtm_deladdr(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tb[IFA_MAX+1];
	struct in_device *in_dev;
	struct ifaddrmsg *ifm;
	struct in_ifaddr *ifa, **ifap;
	int err = -EINVAL;

	ASSERT_RTNL();

	/*
	  * 解析netlink报文，获取配置参数。
	  */
	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFA_MAX, ifa_ipv4_policy);
	if (err < 0)
		goto errout;

	ifm = nlmsg_data(nlh);
	in_dev = inetdev_by_index(net, ifm->ifa_index);
	if (in_dev == NULL) {
		err = -ENODEV;
		goto errout;
	}

	__in_dev_put(in_dev);

	/*
	  * 根据本地地址、标签以及掩码查找待删除的
	  * IP地址块，如果查找命中，则将其删除并释放。
	  */
	for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
	     ifap = &ifa->ifa_next) {
		if (tb[IFA_LOCAL] &&
		    ifa->ifa_local != nla_get_be32(tb[IFA_LOCAL]))
			continue;

		if (tb[IFA_LABEL] && nla_strcmp(tb[IFA_LABEL], ifa->ifa_label))
			continue;

		if (tb[IFA_ADDRESS] &&
		    (ifm->ifa_prefixlen != ifa->ifa_prefixlen ||
		    !inet_ifa_match(nla_get_be32(tb[IFA_ADDRESS]), ifa)))
			continue;

		__inet_del_ifa(in_dev, ifap, 1, nlh, NETLINK_CB(skb).pid);
		return 0;
	}

	err = -EADDRNOTAVAIL;
errout:
	return err;
}

static struct in_ifaddr *rtm_to_ifaddr(struct net *net, struct nlmsghdr *nlh)
{
	struct nlattr *tb[IFA_MAX+1];
	struct in_ifaddr *ifa;
	struct ifaddrmsg *ifm;
	struct net_device *dev;
	struct in_device *in_dev;
	int err;

	err = nlmsg_parse(nlh, sizeof(*ifm), tb, IFA_MAX, ifa_ipv4_policy);
	if (err < 0)
		goto errout;

	ifm = nlmsg_data(nlh);
	err = -EINVAL;
	if (ifm->ifa_prefixlen > 32 || tb[IFA_LOCAL] == NULL)
		goto errout;

	dev = __dev_get_by_index(net, ifm->ifa_index);
	err = -ENODEV;
	if (dev == NULL)
		goto errout;

	in_dev = __in_dev_get_rtnl(dev);
	err = -ENOBUFS;
	if (in_dev == NULL)
		goto errout;

	ifa = inet_alloc_ifa();
	if (ifa == NULL)
		/*
		 * A potential indev allocation can be left alive, it stays
		 * assigned to its device and is destroy with it.
		 */
		goto errout;

	ipv4_devconf_setall(in_dev);
	in_dev_hold(in_dev);

	if (tb[IFA_ADDRESS] == NULL)
		tb[IFA_ADDRESS] = tb[IFA_LOCAL];

	ifa->ifa_prefixlen = ifm->ifa_prefixlen;
	ifa->ifa_mask = inet_make_mask(ifm->ifa_prefixlen);
	ifa->ifa_flags = ifm->ifa_flags;
	ifa->ifa_scope = ifm->ifa_scope;
	ifa->ifa_dev = in_dev;

	ifa->ifa_local = nla_get_be32(tb[IFA_LOCAL]);
	ifa->ifa_address = nla_get_be32(tb[IFA_ADDRESS]);

	if (tb[IFA_BROADCAST])
		ifa->ifa_broadcast = nla_get_be32(tb[IFA_BROADCAST]);

	if (tb[IFA_LABEL])
		nla_strlcpy(ifa->ifa_label, tb[IFA_LABEL], IFNAMSIZ);
	else
		memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);

	return ifa;

errout:
	return ERR_PTR(err);
}

/*
  * 当通过netlink，操作类型为RTM_NEWADDR添加IP地址
  * 时，会调用此函数
  */
static int inet_rtm_newaddr(struct sk_buff *skb, struct nlmsghdr *nlh, void *arg)
{
	struct net *net = sock_net(skb->sk);
	struct in_ifaddr *ifa;

	ASSERT_RTNL();

	/*
	  * 从配置IP地址的消息中获取地址信息
	  */
	ifa = rtm_to_ifaddr(net, nlh);
	if (IS_ERR(ifa))
		return PTR_ERR(ifa);

	/*
	  * 将IP地址配置到指定的网络设备上
	  */
	return __inet_insert_ifa(ifa, nlh, NETLINK_CB(skb).pid);
}


/*
 *	Determine a default network mask, based on the IP address.
 */
/*
  * inet_abc_len()根据指定的IP地址获取默认掩码
  * 长度。默认掩码长度表:
  * ------------------------------------------
  * 地址			默认掩码长度
  * ------------------------------------------
  * 0地址             0
  * A类地址        8
  * B类地址        16
  * C类地址         24
  */
static __inline__ int inet_abc_len(__be32 addr)
{
	int rc = -1;	/* Something else, probably a multicast. */

	if (ipv4_is_zeronet(addr))
		rc = 0;
	else {
		__u32 haddr = ntohl(addr);

		if (IN_CLASSA(haddr))
			rc = 8;
		else if (IN_CLASSB(haddr))
			rc = 16;
		else if (IN_CLASSC(haddr))
			rc = 24;
	}

	return rc;
}

/*
  * 应用程序对套接字有关接口层地址的ioctl操作，
  * 最终由devinet_ioctl()来处理
  */
int devinet_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	struct ifreq ifr;
	struct sockaddr_in sin_orig;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
	struct in_device *in_dev;
	struct in_ifaddr **ifap = NULL;
	struct in_ifaddr *ifa = NULL;
	struct net_device *dev;
	char *colon;
	int ret = -EFAULT;
	int tryaddrmatch = 0;

	/*
	 *	Fetch the caller's info block into kernel space
	 */

	/*
	  * 从用户空间复制配置参数
	  */
	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		goto out;
	ifr.ifr_name[IFNAMSIZ - 1] = 0;

	/* save original address for comparison */
	/*
	  * 将原始的配置参数保存起来，用于
	  * 后续的比较操作。
	  */
	memcpy(&sin_orig, sin, sizeof(*sin));

	/*
	  * 配置的设备名中如果存在":"，则表示
	  * 配置了别名。由于需要根据名称操作，
	  * 因此先将该设备名截断，后续再恢复
	  */
	colon = strchr(ifr.ifr_name, ':');
	if (colon)
		*colon = 0;

	/*
	  * 根据网络设备名，记载相应的设备驱动
	  * 模块
	  */
	dev_load(net, ifr.ifr_name);

	/*
	  * 进行相关校验。对于获取操作，则检测
	  * 地址族是否为AF_INET；对于设置操作，
	  * 则必须要有相应的特权；而对于SIOCSIFADDR、
	  * SIOCSIFBRDADDR、SIOCSIFDSTADDR和SIOCSIFNETMASK操作，
	  * 地址族也必须是AF_INET。
	  */
	switch (cmd) {
	case SIOCGIFADDR:	/* Get interface address */
	case SIOCGIFBRDADDR:	/* Get the broadcast address */
	case SIOCGIFDSTADDR:	/* Get the destination address */
	case SIOCGIFNETMASK:	/* Get the netmask for the interface */
		/* Note that these ioctls will not sleep,
		   so that we do not impose a lock.
		   One day we will be forced to put shlock here (I mean SMP)
		 */
		tryaddrmatch = (sin_orig.sin_family == AF_INET);
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		break;

	case SIOCSIFFLAGS:
		ret = -EACCES;
		if (!capable(CAP_NET_ADMIN))
			goto out;
		break;
	case SIOCSIFADDR:	/* Set interface address (and family) */
	case SIOCSIFBRDADDR:	/* Set the broadcast address */
	case SIOCSIFDSTADDR:	/* Set the destination address */
	case SIOCSIFNETMASK: 	/* Set the netmask for the interface */
		ret = -EACCES;
		if (!capable(CAP_NET_ADMIN))
			goto out;
		ret = -EINVAL;
		if (sin->sin_family != AF_INET)
			goto out;
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	rtnl_lock();

	ret = -ENODEV;
	/*
	  * 根据网络设备名获取网络设备
	  */
	if ((dev = __dev_get_by_name(net, ifr.ifr_name)) == NULL)
		goto done;

	/*
	  * 恢复配置参数中的标签别名
	  */
	if (colon)
		*colon = ':';

	/*
	  * 取IP配置块，及用户地址标签对应的设备地址
	  * 结构
	  */
	if ((in_dev = __in_dev_get_rtnl(dev)) != NULL) {
		if (tryaddrmatch) {
			/* Matthias Andree */
			/* compare label and address (4.4BSD style) */
			/* note: we only do this for a limited set of ioctls
			   and only if the original address family was AF_INET.
			   This is checked above. */
			for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
			     ifap = &ifa->ifa_next) {
				if (!strcmp(ifr.ifr_name, ifa->ifa_label) &&
				    sin_orig.sin_addr.s_addr ==
							ifa->ifa_address) {
					break; /* found */
				}
			}
		}
		/* we didn't get a match, maybe the application is
		   4.3BSD-style and passed in junk so we fall back to
		   comparing just the label */
		if (!ifa) {
			for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;
			     ifap = &ifa->ifa_next)
				if (!strcmp(ifr.ifr_name, ifa->ifa_label))
					break;
		}
	}

	/*
	  * 设置地址和标志。SIOCSIFFLAGS是设置网络设备
	  * 的标志，SIOCSIFADDR是添加IP地址，这两个操作
	  * 不针对现有的IP地址块。而其他操作
	  * ，如SIOCGIFBRDADDR，都是针对现有的IP地址块，如果
	  * 不存在与配置参数中的标签或地址匹配的IP
	  * 地址块，则不能继续操作。
	  */
	ret = -EADDRNOTAVAIL;
	if (!ifa && cmd != SIOCSIFADDR && cmd != SIOCSIFFLAGS)
		goto done;

	/*
	  * 针对具体的命令进行操作。
	  */
	switch (cmd) {
	/*
	  * 获取指定网络设备的本地IP地址
	  */
	case SIOCGIFADDR:	/* Get interface address */
		sin->sin_addr.s_addr = ifa->ifa_local;
		goto rarok;

	/*
	  * 获取指定网络设备的组播地址
	  */
	case SIOCGIFBRDADDR:	/* Get the broadcast address */
		sin->sin_addr.s_addr = ifa->ifa_broadcast;
		goto rarok;

	/*
	  * 在点对点连接的情况下，获取指定
	  * 网络设备点对点对端的IP地址
	  */
	case SIOCGIFDSTADDR:	/* Get the destination address */
		sin->sin_addr.s_addr = ifa->ifa_address;
		goto rarok;

	/*
	  * 获取指定网络设备的地址掩码
	  */
	case SIOCGIFNETMASK:	/* Get the netmask for the interface */
		sin->sin_addr.s_addr = ifa->ifa_mask;
		goto rarok;

	/*
	  * 获取网络设备的标志
	  */
	case SIOCSIFFLAGS:
		/*
		  * 对于关闭网络设备，如果指定了网络
		  * 设备别名，并且存在与之对应的
		  * IP地址块，则需要删除释放该IP地址块
		  */
		if (colon) {
			ret = -EADDRNOTAVAIL;
			if (!ifa)
				break;
			ret = 0;
			if (!(ifr.ifr_flags & IFF_UP))
				inet_del_ifa(in_dev, ifap, 1);
			break;
		}
		/*
		  * 将地址设置到网络设备中。
		  */
		ret = dev_change_flags(dev, ifr.ifr_flags);
		break;

	/*
	  * 设置指定网络设备的本地地址
	  */
	case SIOCSIFADDR:	/* Set interface address (and family) */
		ret = -EINVAL;
		/*
		  * 根据本地地址默认的掩码长度，校验
		  * 本地地址的有效性
		  */
		if (inet_abc_len(sin->sin_addr.s_addr) < 0)
			break;

		/*
		  * 如果尚未分配IP地址块，则进行分配，
		  * 并将网络设备别名或网络设备名
		  * 设置到地址标签中
		  */
		if (!ifa) {
			ret = -ENOBUFS;
			if ((ifa = inet_alloc_ifa()) == NULL)
				break;
			if (colon)
				memcpy(ifa->ifa_label, ifr.ifr_name, IFNAMSIZ);
			else
				memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
		} else {
			ret = 0;
			if (ifa->ifa_local == sin->sin_addr.s_addr)
				break;
			/*
			  * 首先将对应的IP地址块从地址列表
			  * 中删除
			  */
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_broadcast = 0;
			ifa->ifa_scope = 0;
		}

		/*
		  * 然后设置本地IP地址
		  */
		ifa->ifa_address = ifa->ifa_local = sin->sin_addr.s_addr;

		/*
		  * 接着根据接口是否为点对点设备，来设置
		  * 子网掩码长度和子网掩码。如果是非点对点
		  * 设备，则根据地址的掩码长度和网络掩码
		  * 设置标准广播地址；否则网络掩码长度为32.
		  * 
		  */
		if (!(dev->flags & IFF_POINTOPOINT)) {
			ifa->ifa_prefixlen = inet_abc_len(ifa->ifa_address);
			ifa->ifa_mask = inet_make_mask(ifa->ifa_prefixlen);
			if ((dev->flags & IFF_BROADCAST) &&
			    ifa->ifa_prefixlen < 31)
				ifa->ifa_broadcast = ifa->ifa_address |
						     ~ifa->ifa_mask;
		} else {
			ifa->ifa_prefixlen = 32;
			ifa->ifa_mask = inet_make_mask(32);
		}
		/*
		  * 最后将配置信息再添加到IP地址块列表中
		  */
		ret = inet_set_ifa(dev, ifa);
		break;

	/*
	  * 设置指定网络设备的组播地址
	  */
	case SIOCSIFBRDADDR:	/* Set the broadcast address */
		ret = 0;
		/*
		  * 如果原有的组播地址与待设置的
		  * 组播地址不等，则先得将对应
		  * IP地址块从地址列表中删除，
		  * 然后再将配置信息添加到
		  * IP地址块列表中
		  */
		if (ifa->ifa_broadcast != sin->sin_addr.s_addr) {
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_broadcast = sin->sin_addr.s_addr;
			inet_insert_ifa(ifa);
		}
		break;

	/*
	  * 在点对点连接的情况下，设置指定
	  * 网络设备点对点对端的IP地址
	  */
	case SIOCSIFDSTADDR:	/* Set the destination address */
		ret = 0;
		/*
		  * 只有当原有的网络设备点对点
		  * 对端IP地址与待设置的地址不等时，
		  * 才有必要进行设置。
		  */
		if (ifa->ifa_address == sin->sin_addr.s_addr)
			break;
		ret = -EINVAL;
		/*
		  * 校验待设置的IP地址是否有效
		  */
		if (inet_abc_len(sin->sin_addr.s_addr) < 0)
			break;
		ret = 0;
		/*
		  * 先将对应IP地址块从地址列表删除，
		  * 然后再将待设置的IP地址设置到
		  * IP地址块中并添加到IP地址块列表
		  */
		inet_del_ifa(in_dev, ifap, 0);
		ifa->ifa_address = sin->sin_addr.s_addr;
		inet_insert_ifa(ifa);
		break;

	/*
	  * 设置指定网络设备的地址掩码
	  */
	case SIOCSIFNETMASK: 	/* Set the netmask for the interface */

		/*
		 *	The mask we set must be legal.
		 */
		ret = -EINVAL;
		/*
		  * 检测待设置的掩码是否有效。
		  */
		if (bad_mask(sin->sin_addr.s_addr, 0))
			break;
		ret = 0;
		/*
		  * 原有的掩码与待设置的掩码不等时，
		  * 才有必要进行设置。
		  */
		if (ifa->ifa_mask != sin->sin_addr.s_addr) {
			__be32 old_mask = ifa->ifa_mask;
			/*
			  * 先将对应IP地址块从地址列表中
			  * 删除，接着如果目前的广播地址
			  * 与当前的网络掩码匹配时，则
			  * 重新计算广播地址，最后将其
			  * 设置到IP地址块中，并添加到
			  * IP地址块列表中。
			  */
			inet_del_ifa(in_dev, ifap, 0);
			ifa->ifa_mask = sin->sin_addr.s_addr;
			ifa->ifa_prefixlen = inet_mask_len(ifa->ifa_mask);

			/* See if current broadcast address matches
			 * with current netmask, then recalculate
			 * the broadcast address. Otherwise it's a
			 * funny address, so don't touch it since
			 * the user seems to know what (s)he's doing...
			 */
			if ((dev->flags & IFF_BROADCAST) &&
			    (ifa->ifa_prefixlen < 31) &&
			    (ifa->ifa_broadcast ==
			     (ifa->ifa_local|~old_mask))) {
				ifa->ifa_broadcast = (ifa->ifa_local |
						      ~sin->sin_addr.s_addr);
			}
			inet_insert_ifa(ifa);
		}
		break;
	}
done:
	rtnl_unlock();
out:
	return ret;
rarok:
	rtnl_unlock();
	ret = copy_to_user(arg, &ifr, sizeof(struct ifreq)) ? -EFAULT : 0;
	goto out;
}

static int inet_gifconf(struct net_device *dev, char __user *buf, int len)
{
	struct in_device *in_dev = __in_dev_get_rtnl(dev);
	struct in_ifaddr *ifa;
	struct ifreq ifr;
	int done = 0;

	if (!in_dev)
		goto out;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		if (!buf) {
			done += sizeof(ifr);
			continue;
		}
		if (len < (int) sizeof(ifr))
			break;
		memset(&ifr, 0, sizeof(struct ifreq));
		if (ifa->ifa_label)
			strcpy(ifr.ifr_name, ifa->ifa_label);
		else
			strcpy(ifr.ifr_name, dev->name);

		(*(struct sockaddr_in *)&ifr.ifr_addr).sin_family = AF_INET;
		(*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr.s_addr =
								ifa->ifa_local;

		if (copy_to_user(buf, &ifr, sizeof(struct ifreq))) {
			done = -EFAULT;
			break;
		}
		buf  += sizeof(struct ifreq);
		len  -= sizeof(struct ifreq);
		done += sizeof(struct ifreq);
	}
out:
	return done;
}

/*
  * 在通过输出网络设备向目的地址发送报文时，如果
  * 没有指定源地址，会调用inet_select_addr()来根据给定设备、
  * 目的地址和作用范围，获取给定作用范围内的主IP
  * 地址作为源地址
  * @dev:获取源地址的网络设备
  * @dst:发送报文的目的地址。不为0，返回与目的地址
  *          在同一子网的IP地址(输出网络设备上配置的不同
  *           地址属于不同子网)。等于0，返回本地地址。
  * @scope:地址作用的范围。为RT_SCOPE_HOST时，表示当报文被
  *             送往本地；为RT_SCOPE_LINK，表示报文被送给只在
  *             本地链路上有意义的地址，诸如广播、受限
  *             广播和本地组播；为RT_SCOPE_UNIVERSE，表示当
  *             报文发送到通往远程非直连目的地
  */
__be32 inet_select_addr(const struct net_device *dev, __be32 dst, int scope)
{
	__be32 addr = 0;
	struct in_device *in_dev;
	struct net *net = dev_net(dev);

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev)
		goto no_in_dev;

	/*
	  * 先检测该网络设备上IPv4配置块是否有效，
	  * 通过检测后遍历IPv4配置块的本地IP地址列表，
	  * 获取第一个满足条件(如scope和dst)的本地地址。
	  */
	for_primary_ifa(in_dev) {
		if (ifa->ifa_scope > scope)
			continue;
		if (!dst || inet_ifa_match(dst, ifa)) {
			addr = ifa->ifa_local;
			break;
		}
		if (!addr)
			addr = ifa->ifa_local;
	} endfor_ifa(in_dev);
no_in_dev:
	rcu_read_unlock();

	/*
	  * 如果获得满足条件的地址，则将其返回
	  */
	if (addr)
		goto out;

	/* Not loopback addresses on loopback should be preferred
	   in this case. It is importnat that lo is the first interface
	   in dev_base list.
	 */
	read_lock(&dev_base_lock);
	rcu_read_lock();
	/*
	  * 如果给定配置的地址都不满足由scope和dst限定
	  * 的条件，则尝试其他设备是否满足所要求的
	  * scope的一个IP地址。
	  */
	for_each_netdev(net, dev) {
		if ((in_dev = __in_dev_get_rcu(dev)) == NULL)
			continue;

		for_primary_ifa(in_dev) {
			if (ifa->ifa_scope != RT_SCOPE_LINK &&
			    ifa->ifa_scope <= scope) {
				addr = ifa->ifa_local;
				goto out_unlock_both;
			}
		} endfor_ifa(in_dev);
	}
out_unlock_both:
	read_unlock(&dev_base_lock);
	rcu_read_unlock();
out:
	return addr;
}
EXPORT_SYMBOL(inet_select_addr);

static __be32 confirm_addr_indev(struct in_device *in_dev, __be32 dst,
			      __be32 local, int scope)
{
	int same = 0;
	__be32 addr = 0;

	for_ifa(in_dev) {
		if (!addr &&
		    (local == ifa->ifa_local || !local) &&
		    ifa->ifa_scope <= scope) {
			addr = ifa->ifa_local;
			if (same)
				break;
		}
		if (!same) {
			same = (!local || inet_ifa_match(local, ifa)) &&
				(!dst || inet_ifa_match(dst, ifa));
			if (same && addr) {
				if (local || !dst)
					break;
				/* Is the selected addr into dst subnet? */
				if (inet_ifa_match(addr, ifa))
					break;
				/* No, then can we use new local src? */
				if (ifa->ifa_scope <= scope) {
					addr = ifa->ifa_local;
					break;
				}
				/* search for large dst subnet for addr */
				same = 0;
			}
		}
	} endfor_ifa(in_dev);

	return same ? addr : 0;
}

/*
 * Confirm that local IP address exists using wildcards:
 * - in_dev: only on this interface, 0=any interface
 * - dst: only in the same subnet as dst, 0=any dst
 * - local: address, 0=autoselect the local address
 * - scope: maximum allowed scope value for the local address
 */
/*
  * 用来确认参数中指定的本地地址是否
  * 存在。
  * @in_dev:用来确定是否在指定本地地址的
  *          IP配置块，如果为NULL，则表示
  *          在所有的网络设备上确认本地地址
  * @dst:目的IP地址，当其不为0时，则待确定
  *          的本地地址必须与该地址在同一子网
  *          内。
  * @local:待确认的本地地址，当其为0时，则自动
  *           选择一个本地地址
  * @scope:确认本地地址时允许的最大范围。
  */
__be32 inet_confirm_addr(struct in_device *in_dev,
			 __be32 dst, __be32 local, int scope)
{
	__be32 addr = 0;
	struct net_device *dev;
	struct net *net;

	/*
	  * 如果指定IP配置块，则在该IP配置块
	  * 所属的网络设备上
	  * 确认本地IP地址。确认过程如下:
	  * 调用confirm_addr_indev()在指定的IP配置块上
	  * 查找与参数local给出的IP地址相同，
	  * 与参数dst给出的IP地址在相同子网内，
	  * 且范围小于scope的本地地址。
	  */
	if (scope != RT_SCOPE_LINK)
		return confirm_addr_indev(in_dev, dst, local, scope);

	net = dev_net(in_dev->dev);
	read_lock(&dev_base_lock);
	rcu_read_lock();
	/*
	  * 当没有指定IP配置块时，则在所有的网络
	  * 设备上确认本地IP地址。
	  */
	for_each_netdev(net, dev) {
		if ((in_dev = __in_dev_get_rcu(dev))) {
			addr = confirm_addr_indev(in_dev, dst, local, scope);
			if (addr)
				break;
		}
	}
	rcu_read_unlock();
	read_unlock(&dev_base_lock);

	return addr;
}

/*
 *	Device notifier
 */

int register_inetaddr_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&inetaddr_chain, nb);
}
EXPORT_SYMBOL(register_inetaddr_notifier);

int unregister_inetaddr_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&inetaddr_chain, nb);
}
EXPORT_SYMBOL(unregister_inetaddr_notifier);

/* Rename ifa_labels for a device name change. Make some effort to preserve
 * existing alias numbering and to create unique labels if possible.
*/
static void inetdev_changename(struct net_device *dev, struct in_device *in_dev)
{
	struct in_ifaddr *ifa;
	int named = 0;

	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
		char old[IFNAMSIZ], *dot;

		memcpy(old, ifa->ifa_label, IFNAMSIZ);
		memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
		if (named++ == 0)
			goto skip;
		dot = strchr(old, ':');
		if (dot == NULL) {
			sprintf(old, ":%d", named);
			dot = old;
		}
		if (strlen(dot) + strlen(dev->name) < IFNAMSIZ)
			strcat(ifa->ifa_label, dot);
		else
			strcpy(ifa->ifa_label + (IFNAMSIZ - strlen(dot) - 1), dot);
skip:
		rtmsg_ifa(RTM_NEWADDR, ifa, NULL, 0);
	}
}

static inline bool inetdev_valid_mtu(unsigned mtu)
{
	return mtu >= 68;
}

static void inetdev_send_gratuitous_arp(struct net_device *dev,
					struct in_device *in_dev)

{
	struct in_ifaddr *ifa = in_dev->ifa_list;

	if (!ifa)
		return;

	arp_send(ARPOP_REQUEST, ETH_P_ARP,
		 ifa->ifa_address, dev,
		 ifa->ifa_address, NULL,
		 dev->dev_addr, NULL);
}

/* Called only under RTNL semaphore */

static int inetdev_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *dev = ptr;
	struct in_device *in_dev = __in_dev_get_rtnl(dev);

	ASSERT_RTNL();

	if (!in_dev) {
		if (event == NETDEV_REGISTER) {
			in_dev = inetdev_init(dev);
			if (!in_dev)
				return notifier_from_errno(-ENOMEM);
			if (dev->flags & IFF_LOOPBACK) {
				IN_DEV_CONF_SET(in_dev, NOXFRM, 1);
				IN_DEV_CONF_SET(in_dev, NOPOLICY, 1);
			}
		} else if (event == NETDEV_CHANGEMTU) {
			/* Re-enabling IP */
			if (inetdev_valid_mtu(dev->mtu))
				in_dev = inetdev_init(dev);
		}
		goto out;
	}

	switch (event) {
	case NETDEV_REGISTER:
		printk(KERN_DEBUG "inetdev_event: bug\n");
		dev->ip_ptr = NULL;
		break;
	case NETDEV_UP:
		if (!inetdev_valid_mtu(dev->mtu))
			break;
		if (dev->flags & IFF_LOOPBACK) {
			struct in_ifaddr *ifa = inet_alloc_ifa();

			if (ifa) {
				ifa->ifa_local =
				  ifa->ifa_address = htonl(INADDR_LOOPBACK);
				ifa->ifa_prefixlen = 8;
				ifa->ifa_mask = inet_make_mask(8);
				in_dev_hold(in_dev);
				ifa->ifa_dev = in_dev;
				ifa->ifa_scope = RT_SCOPE_HOST;
				memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);
				inet_insert_ifa(ifa);
			}
		}
		ip_mc_up(in_dev);
		/* fall through */
	case NETDEV_CHANGEADDR:
		if (!IN_DEV_ARP_NOTIFY(in_dev))
			break;
		/* fall through */
	case NETDEV_NOTIFY_PEERS:
		/* Send gratuitous ARP to notify of link change */
		inetdev_send_gratuitous_arp(dev, in_dev);
		break;
	case NETDEV_DOWN:
		ip_mc_down(in_dev);
		break;
	case NETDEV_PRE_TYPE_CHANGE:
		ip_mc_unmap(in_dev);
		break;
	case NETDEV_POST_TYPE_CHANGE:
		ip_mc_remap(in_dev);
		break;
	case NETDEV_CHANGEMTU:
		if (inetdev_valid_mtu(dev->mtu))
			break;
		/* disable IP when MTU is not enough */
	case NETDEV_UNREGISTER:
		inetdev_destroy(in_dev);
		break;
	case NETDEV_CHANGENAME:
		/* Do not notify about label change, this event is
		 * not interesting to applications using netlink.
		 */
		inetdev_changename(dev, in_dev);

		devinet_sysctl_unregister(in_dev);
		devinet_sysctl_register(in_dev);
		break;
	}
out:
	return NOTIFY_DONE;
}

static struct notifier_block ip_netdev_notifier = {
	.notifier_call = inetdev_event,
};

static inline size_t inet_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ifaddrmsg))
	       + nla_total_size(4) /* IFA_ADDRESS */
	       + nla_total_size(4) /* IFA_LOCAL */
	       + nla_total_size(4) /* IFA_BROADCAST */
	       + nla_total_size(IFNAMSIZ); /* IFA_LABEL */
}

static int inet_fill_ifaddr(struct sk_buff *skb, struct in_ifaddr *ifa,
			    u32 pid, u32 seq, int event, unsigned int flags)
{
	struct ifaddrmsg *ifm;
	struct nlmsghdr  *nlh;

	nlh = nlmsg_put(skb, pid, seq, event, sizeof(*ifm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ifm = nlmsg_data(nlh);
	ifm->ifa_family = AF_INET;
	ifm->ifa_prefixlen = ifa->ifa_prefixlen;
	ifm->ifa_flags = ifa->ifa_flags|IFA_F_PERMANENT;
	ifm->ifa_scope = ifa->ifa_scope;
	ifm->ifa_index = ifa->ifa_dev->dev->ifindex;

	if (ifa->ifa_address)
		NLA_PUT_BE32(skb, IFA_ADDRESS, ifa->ifa_address);

	if (ifa->ifa_local)
		NLA_PUT_BE32(skb, IFA_LOCAL, ifa->ifa_local);

	if (ifa->ifa_broadcast)
		NLA_PUT_BE32(skb, IFA_BROADCAST, ifa->ifa_broadcast);

	if (ifa->ifa_label[0])
		NLA_PUT_STRING(skb, IFA_LABEL, ifa->ifa_label);

	return nlmsg_end(skb, nlh);

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static int inet_dump_ifaddr(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	int h, s_h;
	int idx, s_idx;
	int ip_idx, s_ip_idx;
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	struct hlist_head *head;
	struct hlist_node *node;

	s_h = cb->args[0];
	s_idx = idx = cb->args[1];
	s_ip_idx = ip_idx = cb->args[2];

	for (h = s_h; h < NETDEV_HASHENTRIES; h++, s_idx = 0) {
		idx = 0;
		head = &net->dev_index_head[h];
		rcu_read_lock();
		hlist_for_each_entry_rcu(dev, node, head, index_hlist) {
			if (idx < s_idx)
				goto cont;
			if (h > s_h || idx > s_idx)
				s_ip_idx = 0;
			in_dev = __in_dev_get_rcu(dev);
			if (!in_dev)
				goto cont;

			for (ifa = in_dev->ifa_list, ip_idx = 0; ifa;
			     ifa = ifa->ifa_next, ip_idx++) {
				if (ip_idx < s_ip_idx)
					continue;
				if (inet_fill_ifaddr(skb, ifa,
					     NETLINK_CB(cb->skb).pid,
					     cb->nlh->nlmsg_seq,
					     RTM_NEWADDR, NLM_F_MULTI) <= 0) {
					rcu_read_unlock();
					goto done;
				}
			}
cont:
			idx++;
		}
		rcu_read_unlock();
	}

done:
	cb->args[0] = h;
	cb->args[1] = idx;
	cb->args[2] = ip_idx;

	return skb->len;
}

static void rtmsg_ifa(int event, struct in_ifaddr *ifa, struct nlmsghdr *nlh,
		      u32 pid)
{
	struct sk_buff *skb;
	u32 seq = nlh ? nlh->nlmsg_seq : 0;
	int err = -ENOBUFS;
	struct net *net;

	net = dev_net(ifa->ifa_dev->dev);
	skb = nlmsg_new(inet_nlmsg_size(), GFP_KERNEL);
	if (skb == NULL)
		goto errout;

	err = inet_fill_ifaddr(skb, ifa, pid, seq, event, 0);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in inet_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, pid, RTNLGRP_IPV4_IFADDR, nlh, GFP_KERNEL);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_IPV4_IFADDR, err);
}

#ifdef CONFIG_SYSCTL

static void devinet_copy_dflt_conf(struct net *net, int i)
{
	struct net_device *dev;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		struct in_device *in_dev;

		in_dev = __in_dev_get_rcu(dev);
		if (in_dev && !test_bit(i, in_dev->cnf.state))
			in_dev->cnf.data[i] = net->ipv4.devconf_dflt->data[i];
	}
	rcu_read_unlock();
}

/* called with RTNL locked */
static void inet_forward_change(struct net *net)
{
	struct net_device *dev;
	int on = IPV4_DEVCONF_ALL(net, FORWARDING);

	IPV4_DEVCONF_ALL(net, ACCEPT_REDIRECTS) = !on;
	IPV4_DEVCONF_DFLT(net, FORWARDING) = on;

	for_each_netdev(net, dev) {
		struct in_device *in_dev;
		if (on)
			dev_disable_lro(dev);
		rcu_read_lock();
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev)
			IN_DEV_CONF_SET(in_dev, FORWARDING, on);
		rcu_read_unlock();
	}
}

static int devinet_conf_proc(ctl_table *ctl, int write,
			     void __user *buffer,
			     size_t *lenp, loff_t *ppos)
{
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	if (write) {
		struct ipv4_devconf *cnf = ctl->extra1;
		struct net *net = ctl->extra2;
		int i = (int *)ctl->data - cnf->data;

		set_bit(i, cnf->state);

		if (cnf == net->ipv4.devconf_dflt)
			devinet_copy_dflt_conf(net, i);
	}

	return ret;
}

static int devinet_sysctl_forward(ctl_table *ctl, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos)
{
	int *valp = ctl->data;
	int val = *valp;
	loff_t pos = *ppos;
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	if (write && *valp != val) {
		struct net *net = ctl->extra2;

		if (valp != &IPV4_DEVCONF_DFLT(net, FORWARDING)) {
			if (!rtnl_trylock()) {
				/* Restore the original values before restarting */
				*valp = val;
				*ppos = pos;
				return restart_syscall();
			}
			if (valp == &IPV4_DEVCONF_ALL(net, FORWARDING)) {
				inet_forward_change(net);
			} else if (*valp) {
				struct ipv4_devconf *cnf = ctl->extra1;
				struct in_device *idev =
					container_of(cnf, struct in_device, cnf);
				dev_disable_lro(idev->dev);
			}
			rtnl_unlock();
			rt_cache_flush(net, 0);
		}
	}

	return ret;
}

int ipv4_doint_and_flush(ctl_table *ctl, int write,
			 void __user *buffer,
			 size_t *lenp, loff_t *ppos)
{
	int *valp = ctl->data;
	int val = *valp;
	int ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	struct net *net = ctl->extra2;

	if (write && *valp != val)
		rt_cache_flush(net, 0);

	return ret;
}

#define DEVINET_SYSCTL_ENTRY(attr, name, mval, proc) \
	{ \
		.procname	= name, \
		.data		= ipv4_devconf.data + \
				  IPV4_DEVCONF_ ## attr - 1, \
		.maxlen		= sizeof(int), \
		.mode		= mval, \
		.proc_handler	= proc, \
		.extra1		= &ipv4_devconf, \
	}

#define DEVINET_SYSCTL_RW_ENTRY(attr, name) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0644, devinet_conf_proc)

#define DEVINET_SYSCTL_RO_ENTRY(attr, name) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0444, devinet_conf_proc)

#define DEVINET_SYSCTL_COMPLEX_ENTRY(attr, name, proc) \
	DEVINET_SYSCTL_ENTRY(attr, name, 0644, proc)

#define DEVINET_SYSCTL_FLUSHING_ENTRY(attr, name) \
	DEVINET_SYSCTL_COMPLEX_ENTRY(attr, name, ipv4_doint_and_flush)

static struct devinet_sysctl_table {
	struct ctl_table_header *sysctl_header;
	struct ctl_table devinet_vars[__IPV4_DEVCONF_MAX];
	char *dev_name;
} devinet_sysctl = {
	.devinet_vars = {
		DEVINET_SYSCTL_COMPLEX_ENTRY(FORWARDING, "forwarding",
					     devinet_sysctl_forward),
		DEVINET_SYSCTL_RO_ENTRY(MC_FORWARDING, "mc_forwarding"),

		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_REDIRECTS, "accept_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(SECURE_REDIRECTS, "secure_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(SHARED_MEDIA, "shared_media"),
		DEVINET_SYSCTL_RW_ENTRY(RP_FILTER, "rp_filter"),
		DEVINET_SYSCTL_RW_ENTRY(SEND_REDIRECTS, "send_redirects"),
		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_SOURCE_ROUTE,
					"accept_source_route"),
		DEVINET_SYSCTL_RW_ENTRY(ACCEPT_LOCAL, "accept_local"),
		DEVINET_SYSCTL_RW_ENTRY(SRC_VMARK, "src_valid_mark"),
		DEVINET_SYSCTL_RW_ENTRY(PROXY_ARP, "proxy_arp"),
		DEVINET_SYSCTL_RW_ENTRY(MEDIUM_ID, "medium_id"),
		DEVINET_SYSCTL_RW_ENTRY(BOOTP_RELAY, "bootp_relay"),
		DEVINET_SYSCTL_RW_ENTRY(LOG_MARTIANS, "log_martians"),
		DEVINET_SYSCTL_RW_ENTRY(TAG, "tag"),
		DEVINET_SYSCTL_RW_ENTRY(ARPFILTER, "arp_filter"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_ANNOUNCE, "arp_announce"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_IGNORE, "arp_ignore"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_ACCEPT, "arp_accept"),
		DEVINET_SYSCTL_RW_ENTRY(ARP_NOTIFY, "arp_notify"),
		DEVINET_SYSCTL_RW_ENTRY(PROXY_ARP_PVLAN, "proxy_arp_pvlan"),

		DEVINET_SYSCTL_FLUSHING_ENTRY(NOXFRM, "disable_xfrm"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(NOPOLICY, "disable_policy"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(FORCE_IGMP_VERSION,
					      "force_igmp_version"),
		DEVINET_SYSCTL_FLUSHING_ENTRY(PROMOTE_SECONDARIES,
					      "promote_secondaries"),
	},
};

static int __devinet_sysctl_register(struct net *net, char *dev_name,
					struct ipv4_devconf *p)
{
	int i;
	struct devinet_sysctl_table *t;

#define DEVINET_CTL_PATH_DEV	3

	struct ctl_path devinet_ctl_path[] = {
		{ .procname = "net",  },
		{ .procname = "ipv4", },
		{ .procname = "conf", },
		{ /* to be set */ },
		{ },
	};

	t = kmemdup(&devinet_sysctl, sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	for (i = 0; i < ARRAY_SIZE(t->devinet_vars) - 1; i++) {
		t->devinet_vars[i].data += (char *)p - (char *)&ipv4_devconf;
		t->devinet_vars[i].extra1 = p;
		t->devinet_vars[i].extra2 = net;
	}

	/*
	 * Make a copy of dev_name, because '.procname' is regarded as const
	 * by sysctl and we wouldn't want anyone to change it under our feet
	 * (see SIOCSIFNAME).
	 */
	t->dev_name = kstrdup(dev_name, GFP_KERNEL);
	if (!t->dev_name)
		goto free;

	devinet_ctl_path[DEVINET_CTL_PATH_DEV].procname = t->dev_name;

	t->sysctl_header = register_net_sysctl_table(net, devinet_ctl_path,
			t->devinet_vars);
	if (!t->sysctl_header)
		goto free_procname;

	p->sysctl = t;
	return 0;

free_procname:
	kfree(t->dev_name);
free:
	kfree(t);
out:
	return -ENOBUFS;
}

static void __devinet_sysctl_unregister(struct ipv4_devconf *cnf)
{
	struct devinet_sysctl_table *t = cnf->sysctl;

	if (t == NULL)
		return;

	cnf->sysctl = NULL;
	unregister_sysctl_table(t->sysctl_header);
	kfree(t->dev_name);
	kfree(t);
}

static void devinet_sysctl_register(struct in_device *idev)
{
	neigh_sysctl_register(idev->dev, idev->arp_parms, "ipv4", NULL);
	__devinet_sysctl_register(dev_net(idev->dev), idev->dev->name,
					&idev->cnf);
}

static void devinet_sysctl_unregister(struct in_device *idev)
{
	__devinet_sysctl_unregister(&idev->cnf);
	neigh_sysctl_unregister(idev->arp_parms);
}

static struct ctl_table ctl_forward_entry[] = {
	{
		.procname	= "ip_forward",
		.data		= &ipv4_devconf.data[
					IPV4_DEVCONF_FORWARDING - 1],
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= devinet_sysctl_forward,
		.extra1		= &ipv4_devconf,
		.extra2		= &init_net,
	},
	{ },
};

static __net_initdata struct ctl_path net_ipv4_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv4", },
	{ },
};
#endif

static __net_init int devinet_init_net(struct net *net)
{
	int err;
	struct ipv4_devconf *all, *dflt;
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl = ctl_forward_entry;
	struct ctl_table_header *forw_hdr;
#endif

	err = -ENOMEM;
	all = &ipv4_devconf;
	dflt = &ipv4_devconf_dflt;

	if (!net_eq(net, &init_net)) {
		all = kmemdup(all, sizeof(ipv4_devconf), GFP_KERNEL);
		if (all == NULL)
			goto err_alloc_all;

		dflt = kmemdup(dflt, sizeof(ipv4_devconf_dflt), GFP_KERNEL);
		if (dflt == NULL)
			goto err_alloc_dflt;

#ifdef CONFIG_SYSCTL
		tbl = kmemdup(tbl, sizeof(ctl_forward_entry), GFP_KERNEL);
		if (tbl == NULL)
			goto err_alloc_ctl;

		tbl[0].data = &all->data[IPV4_DEVCONF_FORWARDING - 1];
		tbl[0].extra1 = all;
		tbl[0].extra2 = net;
#endif
	}

#ifdef CONFIG_SYSCTL
	err = __devinet_sysctl_register(net, "all", all);
	if (err < 0)
		goto err_reg_all;

	err = __devinet_sysctl_register(net, "default", dflt);
	if (err < 0)
		goto err_reg_dflt;

	err = -ENOMEM;
	forw_hdr = register_net_sysctl_table(net, net_ipv4_path, tbl);
	if (forw_hdr == NULL)
		goto err_reg_ctl;
	net->ipv4.forw_hdr = forw_hdr;
#endif

	net->ipv4.devconf_all = all;
	net->ipv4.devconf_dflt = dflt;
	return 0;

#ifdef CONFIG_SYSCTL
err_reg_ctl:
	__devinet_sysctl_unregister(dflt);
err_reg_dflt:
	__devinet_sysctl_unregister(all);
err_reg_all:
	if (tbl != ctl_forward_entry)
		kfree(tbl);
err_alloc_ctl:
#endif
	if (dflt != &ipv4_devconf_dflt)
		kfree(dflt);
err_alloc_dflt:
	if (all != &ipv4_devconf)
		kfree(all);
err_alloc_all:
	return err;
}

static __net_exit void devinet_exit_net(struct net *net)
{
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl;

	tbl = net->ipv4.forw_hdr->ctl_table_arg;
	unregister_net_sysctl_table(net->ipv4.forw_hdr);
	__devinet_sysctl_unregister(net->ipv4.devconf_dflt);
	__devinet_sysctl_unregister(net->ipv4.devconf_all);
	kfree(tbl);
#endif
	kfree(net->ipv4.devconf_dflt);
	kfree(net->ipv4.devconf_all);
}

static __net_initdata struct pernet_operations devinet_ops = {
	.init = devinet_init_net,
	.exit = devinet_exit_net,
};

void __init devinet_init(void)
{
	register_pernet_subsys(&devinet_ops);

	register_gifconf(PF_INET, inet_gifconf);
	register_netdevice_notifier(&ip_netdev_notifier);

	rtnl_register(PF_INET, RTM_NEWADDR, inet_rtm_newaddr, NULL);
	rtnl_register(PF_INET, RTM_DELADDR, inet_rtm_deladdr, NULL);
	rtnl_register(PF_INET, RTM_GETADDR, NULL, inet_dump_ifaddr);
}


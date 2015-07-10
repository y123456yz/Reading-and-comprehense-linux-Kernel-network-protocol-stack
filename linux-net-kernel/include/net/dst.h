/*
 * net/dst.h	Protocol independent destination cache definitions.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#ifndef _NET_DST_H
#define _NET_DST_H

#include <net/dst_ops.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <net/neighbour.h>
#include <asm/processor.h>

/*
 * 0 - no debugging messages
 * 1 - rare events and bugs (default)
 * 2 - trace mode.
 */
#define RT_CACHE_DEBUG		0

#define DST_GC_MIN	(HZ/10)
#define DST_GC_INC	(HZ/2)
#define DST_GC_MAX	(120*HZ)

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

/* Each dst_entry has reference count and sits in some parent list(s).
 * When it is removed from parent list, it is "freed" (dst_free).
 * After this it enters dead state (dst->obsolete > 0) and if its refcnt
 * is zero, it can be destroyed immediately, otherwise it is added
 * to gc list and garbage collector periodically checks the refcnt.
 */

struct sk_buff;

/*
 * dst_entry结构被用于存储缓存路由项中独立于
 * 协议的信息。三层协议在另外的结构中存储
 * 本协议中更多的私有信息(例如，IPv4使用
 * rtable结构)。
 */
struct dst_entry
{
	/*
	 * 互斥处理
	 */
	struct rcu_head		rcu_head;
	/*
	 * 与IPsec相关
	 */
	struct dst_entry	*child;
	/*
	 * 输出网络设备(即将报文送达目的地的
	 * 发送设备)。
	 */
	struct net_device       *dev;
	/*
	 * 当fib_lookup()查找失败时，错误码值会被保存
	 * 在这个字段中，在之后ip_error()中使用该值
	 * 来决定如何处理本次路由查找失败，即
	 * 决定生成哪一类ICMP消息。
	 */
	short			error;
	/*
	 * 用于标识本dst_entry实例的可用状态，可选值:
	 * 0(默认值): 表示所在结构实例有效并且可以
	 *                        被使用
	 * 2: 表示所在结构实例将被删除因而不能被使用
	 * -1: 被IPsec和IPv6使用但不被IPv4使用
	 */
	short			obsolete;
	/*
	 * 标志集合，可选的值为DST_HOST等。
	 */
	int			flags;
/*
 * 表示主机路由，既不是到网络或
 * 到一个广播/组播地址的路由。
 */
#define DST_HOST		1
/*
 * 下面三个只用于IPsec。
 */
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
#define DST_NOHASH		8
	/*
	 * 表示该表项将过期的时间戳
	 */
	unsigned long		expires;

	/*
	 * 与IPsec相关
	 */
	unsigned short		header_len;	/* more space at head required */
	/*
	 * 与IPsec相关
	 */
	unsigned short		trailer_len;	/* space to reserve at tail */

	/*
	 * 这两个字段被用于对这两种类型的ICMP
	 * 消息限速。
	 * rate_last为上一个ICMP重定向消息送出的
	 * 时间戳。rate_tokens是已经向与该dst_entry实例
	 * 相关的目的地发送ICMP重定向消息的次数，
	 * 因此，(rate_tokens - 1)也就是连续被目的地忽略
	 * 的ICMP重定向消息的数目。
	 */
	unsigned int		rate_tokens;
	unsigned long		rate_last;	/* rate limiting for ICMP */

	/*
	 * 与IPsec相关
	 */
	struct dst_entry	*path;

	/*
	 *  neighbour是包含下一跳三层地址到二层地址
	 * 映射的结构，hh是缓存的二层首部。
	 */
	struct neighbour	*neighbour;
	struct hh_cache		*hh;
#ifdef CONFIG_XFRM
	/*
	 * 与IPsec相关
	 */
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
        /*
         * 对需要交付到本地的分组，input设置为ip_local_deliver,
         * 而output设置为ip_rt_bug(该函数只向内核日志输出一个
         * 错误信息,因为在内核代码中对本地分组调用output是
         * 一种错误,不应该发生)
         * 对需要转发的分组，input设置为ip_forward,而output设置为
         * ip_output函数
         */
       /* 处理进入的分组*/
	int			(*input)(struct sk_buff*);
       /* 处理外出的分组*/
	int			(*output)(struct sk_buff*);

	/*
	 * 用于处理dst_entry结构的虚函数
	 * 表结构,设置的是ipv4_dst_ops，参见dst_alloc()函数
	 */
	struct  dst_ops	        *ops;

	/*
	 * 多种度量值，TCP中多处使用。
	 */
	u32			metrics[RTAX_MAX];

#ifdef CONFIG_NET_CLS_ROUTE
	/*
	 * 基于路由表的classifier的标签。
	 */
	__u32			tclassid;
#else
	__u32			__pad2;
#endif


	/*
	 * Align __refcnt to a 64 bytes alignment
	 * (L1_CACHE_SIZE would be too much)
	 */
#ifdef CONFIG_64BIT
	long			__pad_to_align_refcnt[2];
#else
	long			__pad_to_align_refcnt[1];
#endif
	/*
	 * __refcnt wants to be on a different cache line from
	 * input/output/ops or performance tanks badly
	 */
	/*
	 * 引用计数
	 */
	atomic_t		__refcnt;	/* client references	*/
	/*
	 * 该表项已经被使用的次数(即缓存
	 * 查找返回该表项的次数)。
	 * 注意:不要这个值与rt_cache_stat[smp_processor_id()].in_hit混淆，
	 * 后者表示针对某个CPU的全局缓存命中次数。
	 */
	int			__use;
	/*
	 * 记录该表项最后一次被使用的时间戳。当
	 * 缓存查找成功时更新该时间戳，垃圾回收
	 * 程序使用该时间戳来决定最应该被释放
	 * 表项。
	 */
	unsigned long		lastuse;
	union {
	/*
	 * next成员用于将分布在同一个散列表
	 * 桶内的dst_entry实例链接在一起。
	 */
		struct dst_entry *next;
		struct rtable    *rt_next;
		struct rt6_info   *rt6_next;
		struct dn_route  *dn_next;
	};
};

struct dst_entry11 {
	struct rcu_head		rcu_head;
	struct dst_entry	*child;
	struct net_device       *dev;
	short			error;
	short			obsolete;
	int			flags;
#define DST_HOST		1
#define DST_NOXFRM		2
#define DST_NOPOLICY		4
#define DST_NOHASH		8
	unsigned long		expires;

	unsigned short		header_len;	/* more space at head required */
	unsigned short		trailer_len;	/* space to reserve at tail */

	unsigned int		rate_tokens;
	unsigned long		rate_last;	/* rate limiting for ICMP */

	struct dst_entry	*path;

	struct neighbour	*neighbour;
	struct hh_cache		*hh;
#ifdef CONFIG_XFRM
	struct xfrm_state	*xfrm;
#else
	void			*__pad1;
#endif
	int			(*input)(struct sk_buff*);
	int			(*output)(struct sk_buff*);

	struct  dst_ops	        *ops;

	u32			metrics[RTAX_MAX];

#ifdef CONFIG_NET_CLS_ROUTE
	__u32			tclassid;
#else
	__u32			__pad2;
#endif


	/*
	 * Align __refcnt to a 64 bytes alignment
	 * (L1_CACHE_SIZE would be too much)
	 */
#ifdef CONFIG_64BIT
	long			__pad_to_align_refcnt[1];
#endif
	/*
	 * __refcnt wants to be on a different cache line from
	 * input/output/ops or performance tanks badly
	 */
	atomic_t		__refcnt;	/* client references	*/
	int			__use;
	unsigned long		lastuse;
	union {
		struct dst_entry *next;
		struct rtable    *rt_next;
		struct rt6_info   *rt6_next;
		struct dn_route  *dn_next;
	};
};

#ifdef __KERNEL__

static inline u32
dst_metric(const struct dst_entry *dst, int metric)
{
	return dst->metrics[metric-1];
}

static inline u32
dst_feature(const struct dst_entry *dst, u32 feature)
{
	return dst_metric(dst, RTAX_FEATURES) & feature;
}

static inline u32 dst_mtu(const struct dst_entry *dst)
{
	u32 mtu = dst_metric(dst, RTAX_MTU);
	/*
	 * Alexey put it here, so ask him about it :)
	 */
	barrier();
	return mtu;
}

/* RTT metrics are stored in milliseconds for user ABI, but used as jiffies */
static inline unsigned long dst_metric_rtt(const struct dst_entry *dst, int metric)
{
	return msecs_to_jiffies(dst_metric(dst, metric));
}

static inline void set_dst_metric_rtt(struct dst_entry *dst, int metric,
				      unsigned long rtt)
{
	dst->metrics[metric-1] = jiffies_to_msecs(rtt);
}

static inline u32
dst_allfrag(const struct dst_entry *dst)
{
	int ret = dst_feature(dst,  RTAX_FEATURE_ALLFRAG);
	/* Yes, _exactly_. This is paranoia. */
	barrier();
	return ret;
}

static inline int
dst_metric_locked(struct dst_entry *dst, int metric)
{
	return dst_metric(dst, RTAX_LOCK) & (1<<metric);
}

static inline void dst_hold(struct dst_entry * dst)
{
	/*
	 * If your kernel compilation stops here, please check
	 * __pad_to_align_refcnt declaration in struct dst_entry
	 */
	BUILD_BUG_ON(offsetof(struct dst_entry, __refcnt) & 63);
	atomic_inc(&dst->__refcnt);
}

static inline void dst_use(struct dst_entry *dst, unsigned long time)
{
	dst_hold(dst);
	dst->__use++;
	dst->lastuse = time;
}

static inline void dst_use_noref(struct dst_entry *dst, unsigned long time)
{
	dst->__use++;
	dst->lastuse = time;
}

static inline
struct dst_entry * dst_clone(struct dst_entry * dst)
{
	if (dst)
		atomic_inc(&dst->__refcnt);
	return dst;
}

extern void dst_release(struct dst_entry *dst);

static inline void refdst_drop(unsigned long refdst)
{
	if (!(refdst & SKB_DST_NOREF))
		dst_release((struct dst_entry *)(refdst & SKB_DST_PTRMASK));
}

/**
 * skb_dst_drop - drops skb dst
 * @skb: buffer
 *
 * Drops dst reference count if a reference was taken.
 */
static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->_skb_refdst) {
		refdst_drop(skb->_skb_refdst);
		skb->_skb_refdst = 0UL;
	}
}

static inline void skb_dst_copy(struct sk_buff *nskb, const struct sk_buff *oskb)
{
	nskb->_skb_refdst = oskb->_skb_refdst;
	if (!(nskb->_skb_refdst & SKB_DST_NOREF))
		dst_clone(skb_dst(nskb));
}

/**
 * skb_dst_force - makes sure skb dst is refcounted
 * @skb: buffer
 *
 * If dst is not yet refcounted, let's do it
 */
static inline void skb_dst_force(struct sk_buff *skb)
{
	if (skb_dst_is_noref(skb)) {
		WARN_ON(!rcu_read_lock_held());
		skb->_skb_refdst &= ~SKB_DST_NOREF;
		dst_clone(skb_dst(skb));
	}
}


/**
 *	skb_tunnel_rx - prepare skb for rx reinsert
 *	@skb: buffer
 *	@dev: tunnel device
 *
 *	After decapsulation, packet is going to re-enter (netif_rx()) our stack,
 *	so make some cleanups, and perform accounting.
 */
static inline void skb_tunnel_rx(struct sk_buff *skb, struct net_device *dev)
{
	skb->dev = dev;
	/* TODO : stats should be SMP safe */
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += skb->len;
	skb->rxhash = 0;
	skb_dst_drop(skb);
	nf_reset(skb);
}

/* Children define the path of the packet through the
 * Linux networking.  Thus, destinations are stackable.
 */

static inline struct dst_entry *skb_dst_pop(struct sk_buff *skb)
{
	struct dst_entry *child = skb_dst(skb)->child;

	skb_dst_drop(skb);
	return child;
}

extern int dst_discard(struct sk_buff *skb);
extern void * dst_alloc(struct dst_ops * ops);
extern void __dst_free(struct dst_entry * dst);
extern struct dst_entry *dst_destroy(struct dst_entry * dst);

static inline void dst_free(struct dst_entry * dst)
{
	if (dst->obsolete > 1)
		return;
	if (!atomic_read(&dst->__refcnt)) {
		dst = dst_destroy(dst);
		if (!dst)
			return;
	}
	__dst_free(dst);
}

static inline void dst_rcu_free(struct rcu_head *head)
{
	struct dst_entry *dst = container_of(head, struct dst_entry, rcu_head);
	dst_free(dst);
}

static inline void dst_confirm(struct dst_entry *dst)
{
	if (dst)
		neigh_confirm(dst->neighbour);
}

static inline void dst_link_failure(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	if (dst && dst->ops && dst->ops->link_failure)
		dst->ops->link_failure(skb);
}

static inline void dst_set_expires(struct dst_entry *dst, int timeout)
{
	unsigned long expires = jiffies + timeout;

	if (expires == 0)
		expires = 1;

	if (dst->expires == 0 || time_before(expires, dst->expires))
		dst->expires = expires;
}

/* Output packet to network from transport.  */
/*
 * 封装了输出数据包目的路由缓存项中
 * 的输出接口。
 */
static inline int dst_output(struct sk_buff *skb)
{
    /*
     * 如果是单播数据包，设置的是ip_output(),
     * 如果是组播数据包，设置的是ip_mc_output().
     */
	return skb_dst(skb)->output(skb); //最终会走到IP层输出函数dev_queue_xmit
}


/* Input packet from network to transport. 
，这个input有可能是ip_local_deliver()或ip_forward()。*/
static inline int dst_input(struct sk_buff *skb)
{
	return skb_dst(skb)->input(skb);
}

static inline struct dst_entry *dst_check(struct dst_entry *dst, u32 cookie)
{
	if (dst->obsolete)
		dst = dst->ops->check(dst, cookie);
	return dst;
}

extern void		dst_init(void);

/* Flags for xfrm_lookup flags argument. */
enum {
	XFRM_LOOKUP_WAIT = 1 << 0,
	XFRM_LOOKUP_ICMP = 1 << 1,
};

struct flowi;
#ifndef CONFIG_XFRM
static inline int xfrm_lookup(struct net *net, struct dst_entry **dst_p,
			      struct flowi *fl, struct sock *sk, int flags)
{
	return 0;
} 
static inline int __xfrm_lookup(struct net *net, struct dst_entry **dst_p,
				struct flowi *fl, struct sock *sk, int flags)
{
	return 0;
}
#else
extern int xfrm_lookup(struct net *net, struct dst_entry **dst_p,
		       struct flowi *fl, struct sock *sk, int flags);
extern int __xfrm_lookup(struct net *net, struct dst_entry **dst_p,
			 struct flowi *fl, struct sock *sk, int flags);
#endif
#endif

#endif /* _NET_DST_H */

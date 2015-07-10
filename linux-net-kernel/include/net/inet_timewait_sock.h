/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for a generic INET TIMEWAIT sock
 *
 *		From code originally in net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_TIMEWAIT_SOCK_
#define _INET_TIMEWAIT_SOCK_


#include <linux/kmemcheck.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/timewait_sock.h>

#include <asm/atomic.h>

struct inet_hashinfo;

#define INET_TWDR_RECYCLE_SLOTS_LOG	5
#define INET_TWDR_RECYCLE_SLOTS		(1 << INET_TWDR_RECYCLE_SLOTS_LOG) //32

/*
 * If time > 4sec, it is "slow" path, no recycling is required,
 * so that we select tick to get range about 4 seconds.
 */
#if HZ <= 16 || HZ > 4096
# error Unsupported: HZ <= 16 or HZ > 4096
#elif HZ <= 32
# define INET_TWDR_RECYCLE_TICK (5 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 64
# define INET_TWDR_RECYCLE_TICK (6 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 128
# define INET_TWDR_RECYCLE_TICK (7 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 256
# define INET_TWDR_RECYCLE_TICK (8 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 512
# define INET_TWDR_RECYCLE_TICK (9 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 1024
# define INET_TWDR_RECYCLE_TICK (10 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#elif HZ <= 2048
# define INET_TWDR_RECYCLE_TICK (11 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#else
# define INET_TWDR_RECYCLE_TICK (12 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#endif

/* TIME_WAIT reaping mechanism. */
#define INET_TWDR_TWKILL_SLOTS	8 /* Please keep this a power of 2. */

#define INET_TWDR_TWKILL_QUOTA 100

struct inet_timewait_death_row1 {
	/* Short-time timewait calendar */
	int			twcal_hand;
	unsigned long		twcal_jiffie;
	struct timer_list	twcal_timer;
	struct hlist_head	twcal_row[INET_TWDR_RECYCLE_SLOTS];

	spinlock_t		death_lock;
	int			tw_count;
	int			period;
	u32			thread_slots;
	struct work_struct	twkill_work;
	struct timer_list	tw_timer;
	int			slot;
	struct hlist_head	cells[INET_TWDR_TWKILL_SLOTS];
	struct inet_hashinfo 	*hashinfo;
	int			sysctl_tw_recycle;
	int			sysctl_max_tw_buckets;
};

/*
在TCP连接的终止过程中，为了便于管理相关的数据，所有的timewait控制块和参数等都存放在inet_timewait_death_row结构中集中管理，TCP的实例为tcp_death_row，其中包括用于
存储timewait控制块的散列表和相应的定时器等。图形化理解可以参考樊东东下册P1002
*/ //对tcp_timewait_sock进行处理                      TCP中该变量赋值的地方在tcp_death_row
struct inet_timewait_death_row { //tcp_timewait_sock的调度过程在inet_twsk_schedule
    /* 下面的这几个2MSL是: 2MSL等待超时时间较短成员变量 */

    
	/* Short-time timewait calendar */
	/*
	 * 初始值为-1，表示twcal_timer定时器
	 * 未使用过，或者使用后已删除。
	 * 当其值不为-1时，表示当前正使用
	 * 的slot，作为每次遍历twcal_row散列表
	 * 的入口。因此在设置超时时间，启动
	 * 定时器后，将其设置为0，表示已开始
	 * 使用
	 */
	int			twcal_hand;
	/*
	 * twcal_timer定时器超时时间，是清除
	 * timewait控制块的阀门
	 */
	unsigned long		twcal_jiffie;
	/*
	 * twcal_timer的超时处理函数是inet_twdr_twcal_tick(),
	 * 它扫描整个twcal_row，删除所有的超时twsk，
	 * 对剩下的twsk重新设定超时时间
	 */
	struct timer_list	twcal_timer;

	/*
	 * TIME_WAIT超时时间除以INET_TWDR_RECYCLE_TICK后
	 * 向上取整，用来判断将该timewait控制块添加
	 * 到cells还是twcal_row散列表中。
	 * 如果得到值大于或等于INET_TWDR_RECYCLE_SLOTS，
	 * 则将其添加到cells散列表中，否则添加到
	 * twcal_row散列表中
	 */
	/*
	 * 用于存储2MSL等待超时时间较短的timewait
	 * 控制块的散列表
	 */
	struct hlist_head	twcal_row[INET_TWDR_RECYCLE_SLOTS]; //里面连接的是tcp_timewait_sock

	/*
	 * 用于同步访问twcal_row和cells散列表的自旋锁
	 */
	spinlock_t		death_lock;
	/*
	 * 当前系统中处于TIME_WAIT状态的套接字数。该值不会
	 * 超过系统参数tcp_max_tw_buckets，参见
	 * NET_TCP_MAX_TW_BUCKETS系统参数
	 */ //在tcp_time_wait中创建inet_timewait_sock后，在inet_twsk_schedule自增加1
	int			tw_count; //在函数inet_twsk_schedule中自增  是当前TIME_WAIT状态套接字的数量





	/* 下面的这几个2MSL是: 2MSL等待超时时间较短成员变量 */

	
	/*
	 * tw_timer定时器的超时时间为
	 * TCP_TIMEWAIT_LEN / INET_TWDR_TWKILL_SLOTS，
	 * 即将60s分成8份
	 */
	int			period;
	/*
	 * 在分批删除并释放cells散列表中的timewait控制块
	 * 时，用于标识待删除slot的位图
	 */
	u32			thread_slots;
	/*
	 * 进行分批删除并释放cells散列表中的timewait
	 * 控制块的工作队列
	 */
	struct work_struct	twkill_work;
	/*
	 * tw_timer的超时处理函数是inet_twdr_hangman()，每
	 * 经过一个period超时一次，取cells中对应的队列，
	 * 删除队列中所有的twsk，同时从ehash散列表
	 * 的后半部分和bash散列表中删除相应的twsk
	 * 及其绑定的本地端口。这批twsk的使命即
	 * 告结束
	 */ //该定时器在这里inet_twsk_schedule触发，真正的定时器处理函数为inet_twdr_hangman,见tcp_death_row
	struct timer_list	tw_timer;
	/*
	 * tw_timer定时器超时时正使用的slot，作为cells
	 * 散列表的关键字 
	 //第一个tw_timer超时的时候，twdr->slot=0,低二个tw_timer超时的时候，该值变1，当到7后又回到1。也就是每隔8个period(TCP_TIMEWAIT_LEN / INET_TWDR_TWKILL_SLOTS)
	 循环一次，这样就可以保证cells表中的所有timewait遍历到(基本上都是INET_TWDR_TWKILL_SLOTS时间遍历到一次本cells，所以时间都是INET_TWDR_TWKILL_SLOTS，除非特殊情况
	 某个cells上的timewait个数超过INET_TWDR_TWKILL_QUOTA见inet_twdr_do_twkill_work)  见inet_twdr_hangman
	 */
	int			slot;//每隔period超时一次
	/*
	 * 用于存储2MSL等待超时时间较长的timewait
	 * 控制块的散列表
	 */
	struct hlist_head	cells[INET_TWDR_TWKILL_SLOTS];
	/*
	 * 指向inet_hashinfo结构类型实例tcp_hashinfo
	 */
	struct inet_hashinfo 	*hashinfo;
	/*  tcp_timestamps参数用来设置是否启用时间戳选项，tcp_tw_recycle参数用来启用快速回收TIME_WAIT套接字。tcp_timestamps参数会影响到
	tcp_tw_recycle参数的效果。如果没有时间戳选项的话，tcp_tw_recycle参数无效，见tcp_time_wait
	 * 用来存储系统参数tcp_tw_recycle的值, tcp_tw_recycle参数用来启用快速回收TIME_WAIT套接字
	 */ //如果启用了tcp_tw_resycle,则tcp_time_wait中超时时间用的tw->tw_timeout = rto，否则是默认的TCP_TIMEWAIT_LEN，TCP_TIMEWAIT_LEN在网络正常的情况下会比rto大，所以启用该参数可以快速回收timewait
    //开启这个的时候，在tcp_v4_conn_request中的后面可能会存在 针对TCP时间戳PAWS漏洞，造成服务器端收到SYN的时候不回收SYN+ACK，解决办法是对方不要发送时间戳选项，同时关闭tcp_timestamps见tcp_v4_conn_request
	int			sysctl_tw_recycle;////在应用层的/proc/sys/net中设置的时候，对应的值会写入到data中
	/*
	 * 用来存储系统参数tcp_max_tw_buckets的值，表示最多可以由多少个time_wait存在
	 */
	int			sysctl_max_tw_buckets;
};

extern void inet_twdr_hangman(unsigned long data);
extern void inet_twdr_twkill_work(struct work_struct *work);
extern void inet_twdr_twcal_tick(unsigned long data);

#if (BITS_PER_LONG == 64)
#define INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES 8
#else
#define INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES 4
#endif

struct inet_bind_bucket;

/*
 * This is a TIME_WAIT sock. It works around the memory consumption
 * problems of sockets in such a state on heavily loaded servers, but
 * without violating the protocol specification.
 *///tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common  TCP连接的时候用 TCP_TIME_WAIT状态过程中用到
 /*
 * inet_timewait_sock结构是支持面向连接特性的
 * TCP_TIME_WAIT状态的描述，是构成tcp_timewait_sock的基础
  tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
 *///当进入TCP连接断开进入timewait状态的时候，该inet_timewait_sock在inet_twsk_schedule中被添加到了tcp_death_row中的tw_death_node中
struct inet_timewait_sock {//该结构在__inet_twsk_kill中最后释放空间
	/*
	 * Now struct sock also uses sock_common, so please just
	 * don't add nothing before this first member (__tw_common) --acme
	 */
	struct sock_common	__tw_common;
#define tw_family		__tw_common.skc_family
#define tw_state		__tw_common.skc_state
#define tw_reuse		__tw_common.skc_reuse
#define tw_bound_dev_if		__tw_common.skc_bound_dev_if
#define tw_node			__tw_common.skc_nulls_node //inet_twsk_add_node_rcu,加入到
#define tw_bind_node		__tw_common.skc_bind_node////在超时状态把inet_bind_bucket桶指向tw->tw_bind_node，避免该函数外面在释放sk的时候，会释放掉bind桶信息
#define tw_refcnt		__tw_common.skc_refcnt
#define tw_hash			__tw_common.skc_hash
#define tw_prot			__tw_common.skc_prot
#define tw_net			__tw_common.skc_net
	/*
	 * 用于记录2MSL超时时间
	 */
	int			tw_timeout;
	/*
	 * 由于TCP状态迁移到FIN_WAIT2或TIME_WAIT状态时，
	 * 都需要由定时器来处理，一旦超时套接字
	 * 随即就被释放。一旦用timewait控制块取代
	 * tcp_sock传输控制块后，其对外的状态时TIME_WAIT，
	 * 而内部状态还是有区别的，因此需要tw_substate
	 * 来标识FIN_WAIT2或TIME_WAIT
	 */
	volatile unsigned char	tw_substate;
	/* 3 bits hole, try to pack */
	unsigned char		tw_rcv_wscale;
	/* Socket demultiplex comparisons on incoming packets. */
	/* these five are in inet_sock */
	//下面这些值都是从inet_sock中获取
	__be16			tw_sport;
	__be32			tw_daddr __attribute__((aligned(INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES)));
	__be32			tw_rcv_saddr;
	__be16			tw_dport;
	__u16			tw_num;
	kmemcheck_bitfield_begin(flags);
	/* And these are ours. */
	unsigned int		tw_ipv6only     : 1,
				tw_transparent  : 1,
				tw_pad		: 14,	/* 14 bits hole */
				tw_ipv6_offset  : 16;
	kmemcheck_bitfield_end(flags);
	/*
	 * 本timewait控制块超时删除的时间(单位为HZ)，
	 * 供proc文件系统等使用
	 */
	unsigned long		tw_ttd;
	/*
	 * 指向绑定的本地端口信息，由对应的TCP传输控制块
	 * 的icsk_bind_hash成员得到。见__inet_twsk_hashdance
	 */
	struct inet_bind_bucket	*tw_tb; //
	/*
	 * 用来在twcal_row和cells散列表中构成链表, 见inet_timewait_death_row
	 */
	struct hlist_node	tw_death_node;
};
struct inet_timewait_sock1 {
	/*
	 * Now struct sock also uses sock_common, so please just
	 * don't add nothing before this first member (__tw_common) --acme
	 */
	struct sock_common	__tw_common;
#define tw_family		__tw_common.skc_family
#define tw_state		__tw_common.skc_state
#define tw_reuse		__tw_common.skc_reuse
#define tw_bound_dev_if		__tw_common.skc_bound_dev_if
#define tw_node			__tw_common.skc_nulls_node
#define tw_bind_node		__tw_common.skc_bind_node
#define tw_refcnt		__tw_common.skc_refcnt
#define tw_hash			__tw_common.skc_hash
#define tw_prot			__tw_common.skc_prot
#define tw_net			__tw_common.skc_net
	int			tw_timeout;
	volatile unsigned char	tw_substate;
	/* 3 bits hole, try to pack */
	unsigned char		tw_rcv_wscale;
	/* Socket demultiplex comparisons on incoming packets. */
	/* these five are in inet_sock */
	__be16			tw_sport;
	__be32			tw_daddr __attribute__((aligned(INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES)));
	__be32			tw_rcv_saddr;
	__be16			tw_dport;
	__u16			tw_num;
	kmemcheck_bitfield_begin(flags);
	/* And these are ours. */
	unsigned int		tw_ipv6only     : 1,
				tw_transparent  : 1,
				tw_pad		: 14,	/* 14 bits hole */
				tw_ipv6_offset  : 16;
	kmemcheck_bitfield_end(flags);
	unsigned long		tw_ttd;
	struct inet_bind_bucket	*tw_tb;
	struct hlist_node	tw_death_node;
};

static inline void inet_twsk_add_node_rcu(struct inet_timewait_sock *tw,
				      struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&tw->tw_node, list);
}

static inline void inet_twsk_add_bind_node(struct inet_timewait_sock *tw,
					   struct hlist_head *list)
{
	hlist_add_head(&tw->tw_bind_node, list);
}

static inline int inet_twsk_dead_hashed(const struct inet_timewait_sock *tw)
{
	return !hlist_unhashed(&tw->tw_death_node);
}

static inline void inet_twsk_dead_node_init(struct inet_timewait_sock *tw)
{
	tw->tw_death_node.pprev = NULL;
}

static inline void __inet_twsk_del_dead_node(struct inet_timewait_sock *tw)
{
	__hlist_del(&tw->tw_death_node);
	inet_twsk_dead_node_init(tw);
}

static inline int inet_twsk_del_dead_node(struct inet_timewait_sock *tw)
{
	if (inet_twsk_dead_hashed(tw)) {
		__inet_twsk_del_dead_node(tw);
		return 1;
	}
	return 0;
}

#define inet_twsk_for_each(tw, node, head) \
	hlist_nulls_for_each_entry(tw, node, head, tw_node)

#define inet_twsk_for_each_inmate(tw, node, jail) \
	hlist_for_each_entry(tw, node, jail, tw_death_node)

#define inet_twsk_for_each_inmate_safe(tw, node, safe, jail) \
	hlist_for_each_entry_safe(tw, node, safe, jail, tw_death_node)

static inline struct inet_timewait_sock *inet_twsk(const struct sock *sk)
{
	return (struct inet_timewait_sock *)sk;
}

static inline __be32 inet_rcv_saddr(const struct sock *sk)
{
	return likely(sk->sk_state != TCP_TIME_WAIT) ?
		inet_sk(sk)->inet_rcv_saddr : inet_twsk(sk)->tw_rcv_saddr;
}

extern void inet_twsk_put(struct inet_timewait_sock *tw);

extern int inet_twsk_unhash(struct inet_timewait_sock *tw);

extern int inet_twsk_bind_unhash(struct inet_timewait_sock *tw,
				 struct inet_hashinfo *hashinfo);

extern struct inet_timewait_sock *inet_twsk_alloc(const struct sock *sk,
						  const int state);

extern void __inet_twsk_hashdance(struct inet_timewait_sock *tw,
				  struct sock *sk,
				  struct inet_hashinfo *hashinfo);

extern void inet_twsk_schedule(struct inet_timewait_sock *tw,
			       struct inet_timewait_death_row *twdr,
			       const int timeo, const int timewait_len);
extern void inet_twsk_deschedule(struct inet_timewait_sock *tw,
				 struct inet_timewait_death_row *twdr);

extern void inet_twsk_purge(struct inet_hashinfo *hashinfo,
			    struct inet_timewait_death_row *twdr, int family);

static inline
struct net *twsk_net(const struct inet_timewait_sock *twsk)
{
#ifdef CONFIG_NET_NS
	return rcu_dereference_raw(twsk->tw_net); /* protected by locking, */
						  /* reference counting, */
						  /* initialization, or RCU. */
#else
	return &init_net;
#endif
}

static inline
void twsk_net_set(struct inet_timewait_sock *twsk, struct net *net)
{
#ifdef CONFIG_NET_NS
	rcu_assign_pointer(twsk->tw_net, net);
#endif
}
#endif	/* _INET_TIMEWAIT_SOCK_ */

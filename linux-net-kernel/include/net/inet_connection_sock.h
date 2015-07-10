/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock 
 *
 * Authors:	Many people, see the TCP sources
 *
 * 		From code originally in TCP
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_CONNECTION_SOCK_H
#define _INET_CONNECTION_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

#define INET_CSK_DEBUG 1

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

struct inet_bind_bucket;
struct tcp_congestion_ops;

/*
 * Pointers to address related TCP functions
 * (i.e. things that depend on the address family)
 */

/*
 * 封装了一组与传输层相关的操作集，包括向网络层发送的接口、传输层的
 * setsockopt接口等。TCP中的实例为ipv4_specific
*/
struct inet_connection_sock_af_ops {
    /* 从传输层向网络层传递的接口，TCP中设置为ip_queue_xmit*/
	int	    (*queue_xmit)(struct sk_buff *skb);

	 /* 计算传输层首部校验和函数，TCP中设置为tcp_v4_send_check*/
	void	    (*send_check)(struct sock *sk, struct sk_buff *skb);

	/* 
     * 如果此传输控制块还没有路由缓存项，为传输控制块选择路由缓存项，
     * TCP中设置为inet_sk_rebuild_header
     */
	int	    (*rebuild_header)(struct sock *sk);

	/* 处理连接请求接口，TCP中设置为tcp_v4_conn_request*/
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);

   /*
     * 在完成三次握手后，调用此接口来创建一个新的套接字，在TCP中初始化
     * 为tcp_v4_syn_recv_sock
     */
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
				      struct request_sock *req,
				      struct dst_entry *dst);

    /*
     * 在启用tw_recycle情况下，关闭套接字时，记录相关时间戳信息到对端信息
     * 管理块中。TCP中设置为tcp_v4_remember_stamp
     */
	int	    (*remember_stamp)(struct sock *sk);
	/* 在IPv4中为IP首部的长度(不带IP首部选项)*/
	u16	    net_header_len;

	 /* IP套接字地址长度，在IPv4中就是sockaddr_in结构的长度*/
	u16	    sockaddr_len;
	int	    (*setsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, unsigned int optlen);
	int	    (*getsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, int __user *optlen);
#ifdef CONFIG_COMPAT
	int	    (*compat_setsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, unsigned int optlen);
	int	    (*compat_getsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int __user *optlen);
#endif

    /*
     * 将IP套接字地址结构中的地址信息复制到传输控制块中，TCP中为
     * inet_csk_addr2sockaddr，实际上该接口并未使用
     */
	void	    (*addr2sockaddr)(struct sock *sk, struct sockaddr *);
	int	    (*bind_conflict)(const struct sock *sk,
				     const struct inet_bind_bucket *tb);
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:	   FIFO of established children 
 * @icsk_bind_hash:	   Bind node
 * @icsk_timeout:	   Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:		   Retransmit timeout
 * @icsk_pmtu_cookie	   Last pmtu seen by socket
 * @icsk_ca_ops		   Pluggable congestion control hook
 * @icsk_af_ops		   Operations which are AF_INET{4,6} specific
 * @icsk_ca_state:	   Congestion control state
 * @icsk_retransmits:	   Number of unrecovered [RTO] timeouts
 * @icsk_pending:	   Scheduled timer event
 * @icsk_backoff:	   Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:	   unanswered 0 window probes
 * @icsk_ext_hdr_len:	   Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:		   Delayed ACK control data
 * @icsk_mtup;		   MTU probing control data
 */
/*套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)
*/
/*以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
//tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock*/

/*
 * inet_connection_sock结构是支持面向连接特性的描述块，构成
 * IPv4协议族TCP控制块的基础，在inet_sock结构的基础上加入了
 * 支持连接的特性。在net_sock基础上增加了连接 确认 重传等选项
 */
struct inet_connection_sock {
    /* inet_sock has to be the first member! */
    struct inet_sock      icsk_inet;
    /*
     * 当TCP传输层接收到客户端的连接请求后，
     * 会创建一个客户端套接字存放
     * 到icsk_accept_queue容器中，等待应用程序
     * 调用accept()进行读取
     */ 
//如果客户端有连接到来，那么在函数tcp_v4_conn_request中的inet_csk_reqsk_queue_hash_add添加到icsk_accept_queue中。直到应用层程序调用accept函数，系统调用
//会执行到inet_csk_accept函数，从而从连接队列中取出这个已连接的信息，也就是队列上面会减少一个，每取一个少一个。服务器端accept的struct sock结构是从这里面去出来的，不是自己创建的
    struct request_sock_queue icsk_accept_queue;  
    /*
     * 指向与之绑定的本地端口信息，在绑定过程中被设置  
     *///inet_bind_bucket也添加到sock的->sk_bind_node中
    struct inet_bind_bucket   *icsk_bind_hash; //存储inet_bind_bucket结构  inet_bind_hash
    /*
     * 如果TCP段在指定时间内没接收到ACK，则认为发送失败，而进行重传的
     * 超时时间jiffies+icsk_rto，即在jiffies+icsk_rto之后进行重传
     */
    unsigned long         icsk_timeout;
    /*
     * 通过标识符icsk_pending来区分重传定时器和持续定时器(窗口探测)的实现。在超时
     * 时间内没有接收到相应的ACK段会发生重传。在连接对方通告接收窗口为
     * 0时会启动持续定时器.
     * 设置的定时器函数为tcp_write_timer().
     */ 
    struct timer_list     icsk_retransmit_timer;//inet_csk_init_xmit_timers
    /* 用于延迟发送ACK段的定时器 
     * 设置的定时器函数为tcp_delack_timer(),参见tcp_v4_init_sock()和
     * tcp_init_xmit_timers().
     * */
    struct timer_list     icsk_delack_timer;//inet_csk_init_xmit_timers  ，在tcp_send_delayed_ack中启用定时器
    /* 
     * 超时重传的时间，初始值为TCP_TIMEOUT_INIT,当往返时间超过此值时被
     * 认为传输失败。需要注意的是，超时重传的时间是根据当前网络的情况
     * 动态计算的。在tcp_v4_init_sock()中初始化。
     * 更新计算过程参见tcp_clean_rtx_queue()和tcp_ack_update_rtt()。
     * 
     * 最大值是TCP_RTO_MAX，最小值是TCP_RTO_MIN
     */
    __u32             icsk_rto;
    /* 最后一次更新的路径MTU(PMTU)  由结构dst_entry中的metrics[RTAX_MAX]初始化并更新 */ //路径MTU发现过程中，如果发送变化会更新。见tcp_sync_mss
    __u32             icsk_pmtu_cookie;
    /*
     * icsk_ca_ops是指向实现某个拥塞控制算法的指针。到目前为止，Linux支持
     * 多种拥塞控制算法，而用户也可以编写自己的拥塞控制机制模块加载到内核
     * 中，参见TCP_CONGESTION选项
     * 
     * 默认情况下是tcp_init_congestion_ops，参见
     * 在初始的时候会设置为tcp_init_congestion_ops(参见tcp_v4_init_sock())，但是在
     * 连接建立过程中会调用tcp_init_congestion_control()选择tcp_cong_list链表中第一个
     * 可以使用的拥塞控制算法模块。在centos下，默认是cubic。
     * 之所以默认是cubic，是因为在编译内核的时候启用了CONFIG_TCP_CONG_CUBIC
     * 选项，参见/boot/config-2.6.32-358.el6.x86_64.
     */
    const struct tcp_congestion_ops *icsk_ca_ops; //可以通过应用程序setsockops设置tcp_setsockopt
    /*
     * TCP的一个操作接口集，包括向IP层发送的接口、TCP层setsockopt接口等。
     * 加载TCP协议模块时，在tcp_v4_init_sock()中被初始化为inet_connection_sock_af_ops
     * 结构类型常量ipv4_specific
     */ ////在tcp_prot->init中被赋值给inet_connection_sock->icsk_af_ops
    const struct inet_connection_sock_af_ops *icsk_af_ops;
    /*
     * 根据PMTU同步本地MSS函数指针。加载TCP协议模块时，在tcp_v4_init_sock()中
     * 被初始化为tcp_sync_mss().
     */
    unsigned int          (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
    /* 拥塞控制状态*/
    __u8              icsk_ca_state;
    /* 记录超时重传的次数,也就是重传的段的个数*/
    __u8              icsk_retransmits;
    /*
     * 标识预定的定时器事件，可能的取值为ICSK_TIME_RETRANS等。实际上，只取
     * ICSK_TIME_RETRANS或ICSK_TIME_PROBE0，因为这两种定时器操作时使用的是
     * 同一个定时器，因此需要用这个标识来区分正在使用的哪个定时器。重传和零
     * 窗口探测时会调用inet_csk_reset_xmit_timer()设置该字段
     */
    __u8              icsk_pending;
    /* 用来计算持续定时器的下一个设定值的指数退避算法指数，在传送超时时会递增 *///例如探测定时器里面tcp_send_probe0，就用了这两个字段做重传时间变化
    __u8              icsk_backoff;
    /*
     * 在建立TCP连接时最多允许重试发送SYN或SYN+ACK段的次数，参见TCP_SYNCNT选项
     * 和sysctl_tcp_synack_retries系统参数
     */
    __u8              icsk_syn_retries;
    /*
     * 持续定时器或保活定时器周期性发送出去但未被确认的TCP段数目，在收到ACK之后
     * 清零
     */
    __u8              icsk_probes_out;
    /* IP首部中选项部分长度 */
    __u16             icsk_ext_hdr_len;
    struct {
        /*
         * 标识当前需要发送确认的紧急程度和状态，可能的取值为ICSK_ACK_SCHED等。
         * 在数据从内核空间复制到用户空间时会检测该状态，如果需要则立即发送确认；
         * 而在计算rcv_mss时，会根据情况调整此状态。由于pending是按位存储的，
         * 因此多个状态可以同时存在
         */
        __u8          pending;   /* ACK is pending             */
        /*
         * 标识在快速发送确认模式中，可以快速发送ACK段的数量。与pingpong
         * 一同作为判断是否在快速发送确认模式下的条件，如果要延时发送确认
         * 则必须在延时发送确认模式下 
         */
        __u8          quick;     /* Scheduled number of quick acks     */
        /*
         * 标识启用或禁止快速确认模式，通过TCP_QUICKACK选项可以设置其值，具体
         * 参见TCP_QUICK选项。取值:
         * 0: 不延时ACK段的发送，而是进行快速发送
         * 1: 将会延时发送ACK
         * 在快速确认模式下，会立即发送ACK.整个TCP处理过程中，如果需要还会进入
         * 到正常模式运行，也就是说，这个标志的设置不是永久性的，而只是在当时
         * 启用/禁止快速确认模式，在这之后，根据延时确认超时、数据传输等因素，
         * 有可能会再次进入或离开快速确认模式
         */
        __u8          pingpong;  /* The session is interactive   见tcp_delack_timer      */
        /*
         * 软中断和用户进程是不能同时占有锁定套接字的，因此如果套接字已被用户
         * 进程锁定，而此时延时ACK定时器被触发，在逻辑上说此时应该发送ACK,但
         * 由于套接字被用户进程锁定了不能访问，因此只能置blocked标志位1，表示
         * "套接字被用户进程锁定了，现不能发送ACK，如果有机会立即发送ACK"，这些
         * 机会包括接收到数据之后和将数据复制到用户空间之后
         */
        __u8          blocked;   /* Delayed ACK was blocked by socket lock */
        /*
         * 用来计算延时确认的估值，在接收到TCP段时会根据本次与上次接收的时间间隔
         * 来调整该值，而在设置延时确认定时器时也会根据条件调整该值
         */
        __u32         ato;       /* Predicted tick of soft clock       */
        /* 当前的延时确认时间，超时时会发送ACK*/
        unsigned long     timeout;   /* Currently scheduled timeout        */
        /* 标识最近一次接收到数据包的时间 */
        __u32         lrcvtime;  /* timestamp of last received data packet */
        /* 最后一个接收到的段的长度，用来计算rcv_mss */
        __u16         last_seg_size; /* Size of last incoming segment      */
        /* 由最近接收到段计算出的MSS，主要用来确定是否执行延时确认*/
        __u16         rcv_mss;   /* MSS used for delayed ACK decisions     */ 
    } icsk_ack; /* 延时确认控制数据块 */
    struct {
        /* 标识是否启用路径MTU发现 */
        int       enabled;

        /* Range of MTUs to search */
        /* 用于标识进行路径MTU发现的区间的上下限 */
        int       search_high;
        int       search_low;

        /* Information on the current probe. */
        /*
         * 为当前路径MTU探测段的长度，也用于判断路径MTU探测是否完成。无论
         * 成功还是失败，路径MTU探测完成后此值都将初始化为0
         */
        int       probe_size;
    } icsk_mtup; /* 有关路径MTU发现的控制数据块，在tcp_mtup_init()中被初始化*/
    /*
     * 存储各种有关TCP拥塞控制算法的私有参数。虽然这里定义的是16个无符号整形，
     * 但在实际存储时的类型因拥塞算法而异
     */
    u32           icsk_ca_priv[16];
#define ICSK_CA_PRIV_SIZE	(16 * sizeof(u32))
};


#define ICSK_TIME_RETRANS	1	/* Retransmit timer */
#define ICSK_TIME_DACK		2	/* Delayed ack timer */
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */
#define ICSK_TIME_KEEPOPEN	4	/* Keepalive timer */

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

extern struct sock *inet_csk_clone(struct sock *sk,
				   const struct request_sock *req,
				   const gfp_t priority);

enum inet_csk_ack_state_t {
    /*
        * 有ACK需要发送，是立即发送还是延时发送，还需要看其他标志，也是能否
        * 发送确认的前提。在接收到有负荷的TCP段后，会设置该标志
        */
	ICSK_ACK_SCHED	= 1, //inet_csk_schedule_ack中置位    ////设置这个标志后，在下一个ack延迟定时器时间到后会发送ack   见tcp_delack_timer
    /* 延时发送ACK定时器已经启动 */
	ICSK_ACK_TIMER  = 2,
    /* 只要有ACK需要发送，并且pingpong为0时，ACK可以立即发送 */
	ICSK_ACK_PUSHED = 4,
	/* 只要有ACK需要发送，都可以立即发送，无论是否处于快速发送模式*/
	ICSK_ACK_PUSHED2 = 8
};

extern void inet_csk_init_xmit_timers(struct sock *sk,
				      void (*retransmit_handler)(unsigned long),
				      void (*delack_handler)(unsigned long),
				      void (*keepalive_handler)(unsigned long));
extern void inet_csk_clear_xmit_timers(struct sock *sk);

//设置这个标志后，在下一个ack延迟定时器时间到后会发送ack   见tcp_delack_timer
static inline void inet_csk_schedule_ack(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_SCHED;
}

static inline int inet_csk_ack_scheduled(const struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pending & ICSK_ACK_SCHED; //tcp_send_delayed_ack
}

static inline void inet_csk_delack_init(struct sock *sk)
{
	memset(&inet_csk(sk)->icsk_ack, 0, sizeof(inet_csk(sk)->icsk_ack));
}

extern void inet_csk_delete_keepalive_timer(struct sock *sk);
extern void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long timeout);

#ifdef INET_CSK_DEBUG
extern const char inet_csk_timer_bug_msg[];
#endif

static inline void inet_csk_clear_xmit_timer(struct sock *sk, const int what)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	
	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
#endif
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.blocked = icsk->icsk_ack.pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_delack_timer);
#endif
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

/*
 *	Reset the retransmission timer
 */
static inline void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
					     unsigned long when,
					     const unsigned long max_when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (when > max_when) {
#ifdef INET_CSK_DEBUG
		pr_debug("reset_xmit_timer: sk=%p %d when=0x%lx, caller=%p\n",
			 sk, what, when, current_text_addr());
#endif
		when = max_when;
	}
    //??疑问:重传定时器和探测定时器为什么后面的定时器不会把前面sk_reset_timer的定时器给覆盖了呢，那前面的定时器不是不起作用吗?
    //因为在启用重传定时器的过程中，表示对端窗口是不为0的，在启动探测定时器的时候也会检查是否有未被确认的ack等。所以他们是不可能同时存在的
	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) { 
		icsk->icsk_pending = what;
		icsk->icsk_timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending |= ICSK_ACK_TIMER;
		icsk->icsk_ack.timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

extern struct sock *inet_csk_accept(struct sock *sk, int flags, int *err);

extern struct request_sock *inet_csk_search_req(const struct sock *sk,
						struct request_sock ***prevp,
						const __be16 rport,
						const __be32 raddr,
						const __be32 laddr);
extern int inet_csk_bind_conflict(const struct sock *sk,
				  const struct inet_bind_bucket *tb);
extern int inet_csk_get_port(struct sock *sk, unsigned short snum);

extern struct dst_entry* inet_csk_route_req(struct sock *sk,
					    const struct request_sock *req);

static inline void inet_csk_reqsk_queue_add(struct sock *sk,
					    struct request_sock *req,
					    struct sock *child)
{
	reqsk_queue_add(&inet_csk(sk)->icsk_accept_queue, req, sk, child);
}

extern void inet_csk_reqsk_queue_hash_add(struct sock *sk,
					  struct request_sock *req,
					  unsigned long timeout);

static inline void inet_csk_reqsk_queue_removed(struct sock *sk,
						struct request_sock *req)
{
	if (reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req) == 0)
		inet_csk_delete_keepalive_timer(sk);
}

static inline void inet_csk_reqsk_queue_added(struct sock *sk,
					      const unsigned long timeout)
{
	if (reqsk_queue_added(&inet_csk(sk)->icsk_accept_queue) == 0) //如果这是sk的第一个半连接则需要启动定时器
		inet_csk_reset_keepalive_timer(sk, timeout);
}

static inline int inet_csk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_young(const struct sock *sk)
{
	return reqsk_queue_len_young(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_is_full(const struct sock *sk)
{
	return reqsk_queue_is_full(&inet_csk(sk)->icsk_accept_queue);
}

static inline void inet_csk_reqsk_queue_unlink(struct sock *sk,
					       struct request_sock *req,
					       struct request_sock **prev)
{
	reqsk_queue_unlink(&inet_csk(sk)->icsk_accept_queue, req, prev);
}

static inline void inet_csk_reqsk_queue_drop(struct sock *sk,
					     struct request_sock *req,
					     struct request_sock **prev)
{
	inet_csk_reqsk_queue_unlink(sk, req, prev);
	inet_csk_reqsk_queue_removed(sk, req);
	reqsk_free(req);
}

extern void inet_csk_reqsk_queue_prune(struct sock *parent,
				       const unsigned long interval,
				       const unsigned long timeout,
				       const unsigned long max_rto);

extern void inet_csk_destroy_sock(struct sock *sk);

/*
 * LISTEN is a special case for poll..
 */
static inline unsigned int inet_csk_listen_poll(const struct sock *sk)
{
	return !reqsk_queue_empty(&inet_csk(sk)->icsk_accept_queue) ?
			(POLLIN | POLLRDNORM) : 0;
}

extern int  inet_csk_listen_start(struct sock *sk, const int nr_table_entries);
extern void inet_csk_listen_stop(struct sock *sk);

extern void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr);

extern int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int __user *optlen);
extern int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, unsigned int optlen);
#endif /* _INET_CONNECTION_SOCK_H */

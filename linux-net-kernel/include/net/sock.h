/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the AF_INET socket handler.
 *
 * Version:	@(#)sock.h	1.0.4	05/13/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche <flla@stud.uni-sb.de>
 *
 * Fixes:
 *		Alan Cox	:	Volatiles in skbuff pointers. See
 *					skbuff comments. May be overdone,
 *					better to prove they can be removed
 *					than the reverse.
 *		Alan Cox	:	Added a zapped field for tcp to note
 *					a socket is reset and must stay shut up
 *		Alan Cox	:	New fields for options
 *	Pauline Middelink	:	identd support
 *		Alan Cox	:	Eliminate low level recv/recvfrom
 *		David S. Miller	:	New socket lookup architecture.
 *              Steve Whitehouse:       Default routines for sock_ops
 *              Arnaldo C. Melo :	removed net_pinfo, tp_pinfo and made
 *              			protinfo be just a void pointer, as the
 *              			protocol specific parts were moved to
 *              			respective headers and ipv4/v6, etc now
 *              			use private slabcaches for its socks
 *              Pedro Hortas	:	New flags field for socket options
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _SOCK_H
#define _SOCK_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/timer.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>	/* struct sk_buff */
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/slab.h>

#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include <linux/poll.h>

#include <asm/atomic.h>
#include <net/dst.h>
#include <net/checksum.h>

/*
 * This structure really needs to be cleaned up.
 * Most of it is for TCP, and not used by any of
 * the other protocols.
 */

/* Define this to get the SOCK_DBG debugging facility. */
#define SOCK_DEBUGGING
#ifdef SOCK_DEBUGGING
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)
#else
/* Validate arguments and do nothing */
static inline void __attribute__ ((format (printf, 2, 3)))
SOCK_DEBUG(struct sock *sk, const char *msg, ...)
{
}
#endif

/* This is the per-socket lock.  The spinlock provides a synchronization
 * between user contexts and software interrupt processing, whereas the
 * mini-semaphore synchronizes multiple users amongst themselves.
 */
 
/*
 * 实现控制用户进程和下半部 (例如应用程序发送数据的时候，然后进入系统调度到内核部分，这时候，内核又收到了对方来的数据，就好产生硬件中断，硬件中断上半部执行完后，执行下半部的时候就会用到刚才被抢走的发送数据的sock，从而会访问相同的数据空间，所以需要枷锁)
 以及下半部之间(例如内核硬件中断接收数据后进入软中断处理过程中，又收到了对方来的数据产生中断。)
 * 间同步锁都是由socket_lock_t结构描述的
 */
typedef struct {
       /*
        * 用来实现下半部间的同步锁,同时也用于保护owned的写操作
        */
    spinlock_t      slock;
       /* 
        * 设置owned时需要通过自旋锁slock来保护，
        * 为0表示未被用户进程锁定，为1表示
        * 被用户进程确定
        */
    int         owned;
       /*
        * 等待队列。当进程调用lock_sock对传输控制块进行上锁时，
        * 如果此时传输控制块已被软中断锁定，则此时进程只能
        * 睡眠，并将进程信息添加到此队列中，当软中断解锁
        * 传输控制块时，会唤醒此队列上的进程
        */
    wait_queue_head_t   wq;
    /*
     * We express the mutex-alike socket_lock semantics
     * to the lock validator by explicitly managing
     * the slock as a lock variant (in addition to
     * the slock itself):
     */
#ifdef CONFIG_DEBUG_LOCK_ALLOC
    struct lockdep_map dep_map;
#endif
} socket_lock_t;


struct sock;
struct proto;
struct net;

/**
 *	struct sock_common - minimal network layer representation of sockets
 *	@skc_node: main hash linkage for various protocol lookup tables
 *	@skc_nulls_node: main hash linkage for TCP/UDP/UDP-Lite protocol
 *	@skc_refcnt: reference count
 *	@skc_tx_queue_mapping: tx queue number for this connection
 *	@skc_hash: hash value used with various protocol lookup tables
 *	@skc_u16hashes: two u16 hash values used by UDP lookup tables
 *	@skc_family: network address family
 *	@skc_state: Connection state
 *	@skc_reuse: %SO_REUSEADDR setting
 *	@skc_bound_dev_if: bound device index if != 0
 *	@skc_bind_node: bind hash linkage for various protocol lookup tables
 *	@skc_portaddr_node: second hash linkage for UDP/UDP-Lite protocol
 *	@skc_prot: protocol handlers inside a network family
 *	@skc_net: reference to the network namespace of this socket
 *
 *	This is the minimal network layer representation of sockets, the header
 *	for struct sock and struct inet_timewait_sock.
 */
/*套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
struct sock里面包含struct sock_common
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)*/

/*
 * 该结构是传输控制块信息的最小集合，由sock和inet_timewait_sock结构
 * 前面相同部分单独构成，因此只用来构成这两种结构
 */
 //tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
/* struct sock里面包含struct sock_common
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
//tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock*/
//sock_common是传输控制块信息最小集合 struct sock是比较通用的网络层描述块，与具体的协议族无关，他描述个各个不同协议族传输层的公共信息
struct sock_common {
    /*
     * first fields are not copied in sock_copy()
     */
    /*
     * TCP维护一个所有TCP传输控制块的散列表tcp_hashinfo,
     * 而skc_node用来将所属TCP传输控制块链接到该散列表，
       udp的hashinfo为udp_table
     */
    union { //udp没有加入到这里面任何一个list中     本段为服务器端的时候tcp和raw在listen的时候调用inet_csk_listen_start把struct sock添加到对应协议的struct proto对应的h成员(hashinfo)中
        struct hlist_node   skc_node;//raw通过raw_hash_sk把sk加入到raw_hashinfo的ht   
        struct hlist_nulls_node skc_nulls_node; //tcp通过inet_hash把sk->skc_nulls_node加入到tcp_hashinfo结构中的listening_hash
    };
    /* 
     * 引用计数，当引用计数为0时才能被释放
     */
    atomic_t        skc_refcnt;

    /*
     * 存储TCP状态为established时加入到散列表的关键字键值。
     * 由于计算键值相对耗时，因此用一个成员来存储键值有利
     * 于提高效率
     */
    unsigned int        skc_hash;
    /*
     * 所属协议族
     */
    unsigned short      skc_family;
    /*
     * 等同于TCP的状态  见TCPF_ESTABLISHED
     */
    volatile unsigned char  skc_state;
    /*
     * 是否可以重用地址和端口  在SO_REUSEADDR中设置，linxu系统中设置地址可重用，端口也可以重用
     端口复用是有条件的，就是sk如果传输控制块允许复用并且不是监听状态sk->sk_state != TCP_LISTEN，见inet_csk_get_port
     */
    unsigned char       skc_reuse;
    /* 如果不为0，即为输出报文的网络设备索引号 */
    int         skc_bound_dev_if; //通过应用程序的setsockopt里面的选项设置
    /*
     * 已绑定端口的传输控制模块利用该字段插入到与之绑定
     * 端口信息结构为头结点的链表中。释放端口时，会从中
     * 删除。仅用于基于连接的传输控制块，如TCP
     *inet_bind_bucket加入到的sk->sk_bind_node中，见inet_bind_hash
     struct sock被添加到inet_bind_bucket结构的owners链表中(inet_bind_hash)，然后该inet_bind_bucket通过node节点加入到tcp_hashinfo中
     */
    struct hlist_node   skc_bind_node;
    struct hlist_nulls_node skc_portaddr_node;//通过函数 ip4_datagram_connect中的udp_v4_rehash添加把udp协议的struct sock添加到udp_table,
    /* 指向网络接口层的指针,如果是TCP套接字，为tcp_prot udp_prot。raw_prot */
    struct proto        *skc_prot;
#ifdef CONFIG_NET_NS
    struct net      *skc_net;
#endif
};

struct sock_common1 {
	/*
	 * first fields are not copied in sock_copy()
	 */
	union {
		struct hlist_node	skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	atomic_t		skc_refcnt;
	int			skc_tx_queue_mapping;

	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	unsigned short		skc_family;
	volatile unsigned char	skc_state;
	unsigned char		skc_reuse;
	int			skc_bound_dev_if;
	union {
		struct hlist_node	skc_bind_node;
		struct hlist_nulls_node skc_portaddr_node;
	};
	struct proto		*skc_prot;
#ifdef CONFIG_NET_NS
	struct net	 	*skc_net;
#endif
};



/**
  *	struct sock - network layer representation of sockets
  *	@__sk_common: shared layout with inet_timewait_sock
  *	@sk_shutdown: mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN
  *	@sk_userlocks: %SO_SNDBUF and %SO_RCVBUF settings
  *	@sk_lock:	synchronizer
  *	@sk_rcvbuf: size of receive buffer in bytes
  *	@sk_wq: sock wait queue and async head
  *	@sk_dst_cache: destination cache
  *	@sk_dst_lock: destination cache lock
  *	@sk_policy: flow policy
  *	@sk_rmem_alloc: receive queue bytes committed
  *	@sk_receive_queue: incoming packets
  *	@sk_wmem_alloc: transmit queue bytes committed
  *	@sk_write_queue: Packet sending queue
  *	@sk_async_wait_queue: DMA copied packets
  *	@sk_omem_alloc: "o" is "option" or "other"
  *	@sk_wmem_queued: persistent queue size
  *	@sk_forward_alloc: space allocated forward
  *	@sk_allocation: allocation mode
  *	@sk_sndbuf: size of send buffer in bytes
  *	@sk_flags: %SO_LINGER (l_onoff), %SO_BROADCAST, %SO_KEEPALIVE,
  *		   %SO_OOBINLINE settings, %SO_TIMESTAMPING settings
  *	@sk_no_check: %SO_NO_CHECK setting, wether or not checkup packets
  *	@sk_route_caps: route capabilities (e.g. %NETIF_F_TSO)
  *	@sk_route_nocaps: forbidden route capabilities (e.g NETIF_F_GSO_MASK)
  *	@sk_gso_type: GSO type (e.g. %SKB_GSO_TCPV4)
  *	@sk_gso_max_size: Maximum GSO segment size to build
  *	@sk_lingertime: %SO_LINGER l_linger setting
  *	@sk_backlog: always used with the per-socket spinlock held
  *	@sk_callback_lock: used with the callbacks in the end of this struct
  *	@sk_error_queue: rarely used
  *	@sk_prot_creator: sk_prot of original sock creator (see ipv6_setsockopt,
  *			  IPV6_ADDRFORM for instance)
  *	@sk_err: last error
  *	@sk_err_soft: errors that don't cause failure but are the cause of a
  *		      persistent failure not just 'timed out'
  *	@sk_drops: raw/udp drops counter
  *	@sk_ack_backlog: current listen backlog
  *	@sk_max_ack_backlog: listen backlog set in listen()
  *	@sk_priority: %SO_PRIORITY setting
  *	@sk_type: socket type (%SOCK_STREAM, etc)
  *	@sk_protocol: which protocol this socket belongs in this network family
  *	@sk_peercred: %SO_PEERCRED setting
  *	@sk_rcvlowat: %SO_RCVLOWAT setting
  *	@sk_rcvtimeo: %SO_RCVTIMEO setting
  *	@sk_sndtimeo: %SO_SNDTIMEO setting
  *	@sk_rxhash: flow hash received from netif layer
  *	@sk_filter: socket filtering instructions
  *	@sk_protinfo: private area, net family specific, when not using slab
  *	@sk_timer: sock cleanup timer
  *	@sk_stamp: time stamp of last packet received
  *	@sk_socket: Identd and reporting IO signals
  *	@sk_user_data: RPC layer private data
  *	@sk_sndmsg_page: cached page for sendmsg
  *	@sk_sndmsg_off: cached offset for sendmsg
  *	@sk_send_head: front of stuff to transmit
  *	@sk_security: used by security modules
  *	@sk_mark: generic packet mark
  *	@sk_write_pending: a write to stream socket waits to start
  *	@sk_state_change: callback to indicate change in the state of the sock
  *	@sk_data_ready: callback to indicate there is data to be processed
  *	@sk_write_space: callback to indicate there is bf sending space available
  *	@sk_error_report: callback to indicate errors (e.g. %MSG_ERRQUEUE)
  *	@sk_backlog_rcv: callback to process the backlog
  *	@sk_destruct: called at sock freeing time, i.e. when all refcnt == 0
 */
 /*struct sock是与具体传输层协议相关的套接字，所有内核的操作都基于这个套接字。
 //传输控制块  struct socket里面的struct sock指向了这里
 //在inet_create中为该结构体分配空间并赋初值。
 /*套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)

struct sock里面包含struct sock_common
/*以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
//tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock

tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)*/
//sock_common是传输控制块信息最小集合 struct sock是比较通用的网络层描述块，与具体的协议族无关，他描述个各个不同协议族传输层的公共信息


//这个struct sock最后根据不同协议分别添加到raw_hashinfo   tcp_hashinfo 做客户端的时候是在connect的时候，通过sk_bind_node成员加入，做服务器端的时候通过
//sk_node或者sk_nulls_node加入到

//inet = inet_sk(sk);tp = tcp_sk(sk);  
struct sock { //TCP情况下的struct sock包括两种，一种称为"父"，另一种为"子"，当应用层调用sock函数的时候，内核创建的是父，当三次握手成功的第三步后会创建新的struct sock,accept的时候会取走这个sock，这个是子
    /*
     * Now struct inet_timewait_sock also uses sock_common, so please just
     * don't add nothing before this first member (__sk_common) --acme
     */
    struct sock_common  __sk_common;
#define sk_node			__sk_common.skc_node //raw通过raw_hash_sk  sk->sk_node加入到raw_hashinfo的ht,相当于struct sock连接到了raw_hashinfo中
#define sk_nulls_node		__sk_common.skc_nulls_node //tcp通过inet_hash把sk->skc_nulls_node加入到tcp_hashinfo结构中的listening_hash。见__sk_nulls_add_node_rcu
#define sk_refcnt		__sk_common.skc_refcnt

#define sk_copy_start		__sk_common.skc_hash 
#define sk_hash			__sk_common.skc_hash
#define sk_family		__sk_common.skc_family

//////sk_flags取值为sock_flags， 状态装换图为前面的sk_state，取值为TCP_SYN_RECV等          sk_state在tcp_set_state中赋值
#define sk_state		__sk_common.skc_state //创建sk的时候，默认为TCP_CLOSE sock_init_data
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if

//客户端tcp在conncet的时候把sk通过inet_bind_bucket加入到tcp_hashinfo中       inet_bind_bucket也被添加到inet_connection_sock中的icsk_bind_hash 
//参考  sk_add_bind_node
#define sk_bind_node		__sk_common.skc_bind_node //见inet_bind_hash    struct sock被添加到inet_bind_bucket结构的owners链表中(inet_bind_hash)，然后该inet_bind_bucket通过node节点加入到tcp_hashinfo中
/* 指向网络接口层的指针,如果是TCP套接字，为tcp_prot
 * 如果是UDP套接字为udp_prot。raw_prot
 * */
#define sk_prot			__sk_common.skc_prot
#define sk_net			__sk_common.skc_net
    kmemcheck_bitfield_begin(flags);
    /*
     * 关闭套接口的标志，下列值之一:
     * RCV_SHUTDOWN: 接收通道关闭，不允许继续接收数据  在接收到FIN并发送ACK的时候，接不能再接收数据了(一种是主动关闭端的第三步FIN和第四步ACK，另一种是被动接收到第一步FIN并发送ACK)。
     * SEND_SHUTDOWN: 发送通道关闭，不允许继续发送数据  在发送FIN并接收到ACK的时候，就不能再发送数据了。(一种是主动关闭的一段发送第一步FIN并受到ACK，另一种是被动端发送第三步FIN并受到ACK)
     * SHUTDOWN_MASK: 表示完全关闭
     */ //如果设置了RCV_SHUTDOWN，则不允许接收数据         如果设置了SEND_SHUTDOWN则不允许接收数据
     //实际起作用的地方是决定是否能接收发送数据
    unsigned int        sk_shutdown  : 2, //在四次挥手过程中可能会用到  
    /*
     * 标识是否对RAW和UDP进行校验和，下列值之一:
     * UDP_CSUM_NOXMIT: 不执行校验和
     * UDP_CSUM_NORCV: 只用于SunRPC
     * UDP_CSUM_DEFAULT: 默认执行校验和
     */
                sk_no_check  : 2, //在setsockops中设置为SO_NO_CHECK的时候生效
     /*
      * 标识传输层的一些状态，下列值之一:
      * SOCK_SNDBUF_LOCK: 用户通过套接口选项设置了发送缓冲区大小
      * SOCK_RCVBUF_LOCK: 用户通过套接口选项设置了接收缓冲区大小
      * SOCK_BINDADDR_LOCK: 已经绑定了本地地址
      * SOCK_BINDPORT_LOCK: 已经绑定了本地端口
      */
                sk_userlocks : 4,
     /*
      * 当前域中套接字所属的协议  IPPROTO_TCP等
      */
                sk_protocol  : 8,
      /* 
       * 所属的套接字类型，如SOCK_STREAM
       */
                sk_type      : 16;
    kmemcheck_bitfield_end(flags);
    /* 接收缓冲区大小的上限，默认值是sysctl_rmem_default(sock_init_data)，即32767， 也就是IP首部16位长度(最大65535)的一半*/
    //当sock接收到一个包的时候，会在sock_queue_rcv_skb中判断当前队列中已有的skb占用的buffer和这个新来的buff之后是否超过了sk_rcvbuf
    int         sk_rcvbuf; //sk_rcvqueues_full函数对接收的包会做一下检查   setsockops中设置  。并能通过tcp_rmem调整。 
    
    /*
     * 同步锁，其中包括了两种锁:一是用于用户进程读取数据
     * 和网络层向传输层传递数据之间的同步锁；二是控制Linux
     * 下半部访问本传输控制块的同步锁，以免多个下半部同
     * 时访问本传输控制块
     */
    socket_lock_t       sk_lock;//被lock_sock使用
    /*
     * The backlog queue is special, it is always used with
     * the per-socket spinlock held and requires low latency
     * access. Therefore we special case it's implementation.
     */
    /*
     * 后备接收队列，目前只用于TCP.传输控制块被上锁后(如应用层
     * 读取数据时),当有新的报文传递到传输控制块时，只能把报文
     * 放到后备接受队列中，之后有用户进程读取TCP数据时，再从
     * 该队列中取出复制到用户空间中.
     * 一旦用户进程解锁传输控制块，就会立即处理
     * 后备队列，将TCP段处理之后添加到接收队列中。
     */
    struct {
        struct sk_buff *head;
        struct sk_buff *tail;
    } sk_backlog;
    /*
     * 进程等待队列。进程等待连接、等待输出缓冲区、等待
     * 读数据时，都会将进程暂存到此队列中。这个成员最初
     * 是在sk_clone()中初始化为NULL，该成员实际存储的socket结构
     * 中的wait成员，这个操作在sock_init_data()中完成。 有的版本这里直接是wait, 唤醒该队列上的进程函数是sock_def_wakeup
     */
    wait_queue_head_t   *sk_sleep;
    /*
     * 目的路由项缓存，一般都是在创建传输控制块发送
     * 数据报文时，发现未设置该字段才从路由表或路由
     * 缓存中查询到相应的路由项来设置新字段，这样可以
     * 加速数据的输出，后续数据的输出不必再查询目的
     * 路由。某些情况下会刷新此目的路由缓存，比如断开
     * 连接、重新进行了连接、TCP重传、重新绑定端口
     * 等操作
     */
    struct dst_entry    *sk_dst_cache;
#ifdef CONFIG_XFRM
    /* 与IPSee相关的传输策略 */
    struct xfrm_policy  *sk_policy[2];
#endif
    /* 操作目的路由缓存的读写锁 */
    rwlock_t        sk_dst_lock;
    /* 接收队列sk_receive_queue中所有报文数据的总长度 .该成员在skb_set_owner_r()函数中会更新*/ //实际在接收SKB开辟空间的时候，会把该值和sk_rcvbuf大小做比较

    ////这个只针对接收数据，发送数据对应的是sk_rmem_alloc， 
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
    atomic_t        sk_rmem_alloc; //表示接收队列中所有skb的总长度，在sock_queue_rcv_skb函数的skb_set_owner_r中增加

    /* 所在传输控制块中，为发送而分配的所有SKB数据区的总长度。这个成员和
     * sk_wmem_queued不同，所有因为发送而分配的SKB数据区的内存都会统计到
     * sk_wmem_alloc成员中。例如，在tcp_transmit_skb()中会克隆发送队列中的
     * SKB，克隆出来的SKB所占的内存会统计到sk_wmem_alloc，而不是sk_wmem_queued中。
     *  
     * 释放sock结构时，会先将sk_wmem_alloc成员减1，如果为0，说明没有待
     * 发送的数据，才会真正释放。所以这里要先将其初始化为1   ,参见 
     * sk_alloc()。
     * 该成员在skb_set_owner_w()中会更新。
     *///通过阅读函数sock_alloc_send_pskb可以理解改变量的作用  每开辟一个SKB的时候当应用程序通过套接口传数据的时候，最终会把数据传输到SKB中，然后把数据长度+header长度的值赋值给该变量中，表示当前该套接字中未发送的数据为多少
// 见sock_alloc_send_pskb中的skb_set_owner_w   在开辟空间前要和sk_sndbuf做比较
//在sk_alloc的时候初始化设置为1，然后在skb_set_owner_w加上SKB长度，当SKB发送出去后，在减去该SKB的长度，所以这个值当数据发送后其值始终是1，不会执行sock_wfree
//这个为发送队列(包括克隆的)分配的实际空间，sk_forward_alloc是提前预分配的，实际上并没有分片空间，只是说先确定下来可以用这么多空间，就是后面分片空间的时候最多可以分片这么多空间。
    atomic_t        sk_wmem_alloc; //这个只针对发送数据，接收数据对应的是sk_rmem_alloc，   //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
    /* 
     * 分配辅助缓冲区的上限，辅助数据包括进行设置选项、
     * 设置过滤时分配到的内存和组播设置等
     */
    atomic_t        sk_omem_alloc;
    /*
     * 发送缓冲区长度的上限，发送队列中报文数据总长度不能
     * 超过该值.默认值是sysctl_wmem_default，即32767。在通过setsockops设置时，其值最大为sysctl_wmem_max的两倍
     */ //发送缓冲区会根据该proto使用的内存情况，进行调整，见__sk_mem_schedule中的sk_stream_moderate_sndbuf        并能通过tcp_rmem调整。 
    int         sk_sndbuf; //setsockops中设置   这个是本sock发送缓存的最大值，整个tcp_prot或者udp_prot的内存情况比较，参考proto相关字段
    /*
     * 接收队列，等待用户进程读取。TCP比较特别，
     * 当接收到的数据不能直接复制到用户空间时才会
     * 缓存在此
     */
    struct sk_buff_head sk_receive_queue;
    /*
     * 发送队列，在TCP中，此队列同时也是重传队列，
     * 在sk_send_head之前为重传队列，之后为发送
     * 队列，参见sk_send_head
     */ //这上面存的是发送SKB链表，即使调用了dev_queue_xmit后,该SKB海在该链表上面，知道收到对方ack。
     //图形化理解参考樊东东下P866
    struct sk_buff_head sk_write_queue;
#ifdef CONFIG_NET_DMA
    /* 与网络设备的DMA相关 */
    struct sk_buff_head sk_async_wait_queue;
#endif
    /* 发送队列中所有报文数据的总长度，目前只用于TCP 。这里
     * 统计的是发送队列中所有报文的长度，不包括因为发送而克隆
     * 出来的SKB占用的内存。是真正的占用空间的发送队列数据长度。见skb_entail
     * */
    int         sk_wmem_queued; //skb_entail中会赋值
    /* 
     * 预分配缓存长度，这只是一个标识，目前 只用于TCP。
     * 当分配的缓存小于该值时，分配必然成功，否则需要
     * 重新确认分配的缓存是否有效。参见__sk_mem_schedule().
     * 在sk_clone()中，sk_forward_alloc被初始化为0.
     * 
     * update:sk_forward_alloc表示预分配长度。当我们第一次要为
     * 发送缓冲队列分配一个struct sk_buff时，我们并不是直接
     * 分配需要的内存大小，而是会以内存页为单位进行
     * 预分配(此时并不是真的分配内存)。当把这个新分配
     * 成功的struct sk_buff放入缓冲队列sk_write_queue后，从sk_forward_alloc
     * 中减去该sk_buff的truesize值。第二次分配struct sk_buff时，只要再
     * 从sk_forward_alloc中减去新的sk_buff的truesize即可，如果sk_forward_alloc
     * 已经小于当前的truesize，则将其再加上一个页的整数倍值，
     * 并累加如tcp_memory_allocated。
     
     *   也就是说，通过sk_forward_alloc使全局变量tcp_memory_allocated保存
     * 当前tcp协议总的缓冲区分配内存的大小，并且该大小是
     * 页边界对齐的。
     */ //这是本sock的缓存大小，如果要看整个tcp sock的缓存大小，要参考tcp_prot中的memory_allocated成员
     ////阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法 。  注意和上面的sk_wmem_alloc的区别
    int         sk_forward_alloc; //skb_entail中的sk_mem_charge里面会对新分配的SKB空间做一次减法，表示预分配缓存空间少了   在真正分配空间之前需要比较这个值，看内存空间释放使用达到限度
    //在应用层send_msg的时候，会在函数__sk_mem_schedule中开辟空间，为sk_forward_alloc增加amt * SK_MEM_QUANTUM;如果发送的数据长度小于该值，肯定超过，若果大于该值
    //则会增加sk_forward_alloc拥有的内存空间，见sk_wmem_schedule
    //该变量表示的是当前sk的可用空间，预分配后的可用空间。例如应用层send，在内核分配ksb的时候空间做减法，表示可用空间少了这部分长度，当发送出去释放skb后，做加法，这时表示可用空间有多了
    
    /*
     * 内存分配方式，参见include\linux\gfp.h。值为__GFP_DMA等
     */
    gfp_t           sk_allocation;
    /*
     * 目的路由网络设备的特性，在sk_setup_caps()中根据
     * net_device结构的features成员设置
     */ //参考//如果网口设备dev设置了dev->features |= NETIF_F_TSO，则支持TSO      参考e1000网卡的这里enic_ethtool_ops
    int         sk_route_caps;
    /*
     * 传输层支持的GSO类型，如SKB_GSO_TCPV4等  默认该值为SKB_GSO_TCPV4
     */
    int         sk_gso_type;//tcp_v4_connect
    /*
     * 这个成员在sk_setup_caps()中初始化，表示最大TCP分段的大小。
     * 注意，这个大小包括IP首部长度长度、IP选项长度及TCP首部和选项，
     * 另外还要减1(这个减1不知道是为什么。。。。)
     */
    unsigned int        sk_gso_max_size;
    /*
     * 标识接收缓存下限值
     */
    int         sk_rcvlowat;
    /*
     * 标志位，可能的取值参见枚举类型sock_flags.
     * 判断某个标志是否设置调用sock_flag函数来
     * 判断，而不是直接使用位操作。
     */
    unsigned long       sk_flags; //////sk_flags取值为sock_flags， 状态装换图为前面的sk_state，取值为TCP_SYN_RECV等
    /* 关闭套接字前发送剩余数据的时间*/
    unsigned long           sk_lingertime; //setsockops中设置 SO_LINGER
    /* 
     * 错误链表，存放详细的出错信息。应用程序通过setsockopt
     * 系统调用设置IP_RECVERR选项，即需获取详细出错信息。当
     * 有错误发生时，可通过recvmsg()，参数flags为MSG_ERRQUEUE
     * 来获取详细的出错信息
     * update:
     * sk_error_queue用于保存错误消息，当ICMP接收到差错消息或者
     * UDP套接字和RAW套接字输出报文出错时，会产生描述错误信息的
     * SKB添加到该队列上。应用程序为能通过系统调用获取详细的
     * 错误消息，需要设置IP_RECVERR套接字选项，之后可通过参数
     * flags为MSG_ERRQUEUE的recvmsg系统调用来获取详细的出错
     * 信息。
     * UDP套接字和RAW套接字在调用recvmsg接收数据时，可以设置
     * MSG_ERRQUEUE标志，只从套接字的错误队列上接收错误而不
     * 接收其他数据。实现这个功能是通过ip_recv_error()来完成的。
     * 在基于连接的套接字上，IP_RECVERR意义则会有所不同。并不
     * 保存错误信息到错误队列中，而是立即传递所有收到的错误信息
     * 给用户进程。这对于基于短连接的TCP应用是很有用的，因为
     * TCP要求快速的错误处理。需要注意的是，TCP没有错误队列，
     * MSG_ERRQUEUE对于基于连接的套接字是无效的。
     * 错误信息传递给用户进程时，并不将错误信息作为报文的内容传递
     * 给用户进程，而是以错误信息块的形式保存在SKB控制块中，
     * 通常通过SKB_EXT_ERR来访问SKB控制块中的错误信息块。
     * 参见sock_exterr_skb结构。
     */
    struct sk_buff_head sk_error_queue;
    /*
     * 原始网络协议块指针。因为传输控制块中的另一个网络
     * 协议块指针sk_prot在IPv6的IPV6_ADDRFORM套接字选项
     * 设置时被修改
     */
    struct proto        *sk_prot_creator;
    /*
     * 确保传输控制块中一些成员同步访问的锁。因为有些成员在软
     * 中断中被访问，存在异步访问的问题
     *
     */
    rwlock_t        sk_callback_lock;
    /*
     * 记录当前传输层中发生的最后一次致命错误的错误码，但
     * 应用层读取后会自动恢复为初始正常状态.
     * 错误码的设置是由tcp_v4_err()函数完成的。
     */
    int         sk_err,
    /*
     * 用于记录非致命性错误，或者用作在传输控制块被
     * 锁定时记录错误的后备成员
     */
                sk_err_soft;
    atomic_t        sk_drops;
    /* 当前已建立的连接数 */  //表示套接口上可以排队等待连接的连接数门限值
    //在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
//这个是从半连接队列取出request_sock后加入到已连接队列中的request_sock个数，sk_ack_backlog是已经完成了三次握手，但是还没有被accept系统调用处理的连接请求数量；sk_max_ack_backlog就是我们经常熟悉的listen的参数。
    unsigned short      sk_ack_backlog;  //建立连接的过程中加1，在reqsk_queue_add中赋值 减1在reqsk_queue_get_child
    /* 连接队列长度的上限 ，其值是用户指定的连接
     * 队列长度与/proc/sys/net/core/somaxconn(默认值是128)之间的较小值。表示该sock上面最多可以由多少个连接，见tcp_v4_conn_request中的sk_acceptq_is_full
     * 用这个变量的sk应该是accept前的那个sk
     */
    unsigned short      sk_max_ack_backlog;//在inet_listen赋值，为listen的第三个参数向上取得的2次密reqsk_queue_alloc，这个值和半连接里面的listen_sock中的nr_table_entries相同
    /* 用于设置由此套接字输出数据包的QoS类别 */
    __u32           sk_priority; //SKB->priority就是用的该字段
    /* 返回连接至该套接字的外部进程的身份验证，目前主要用于PF_UNIX协议族*/
    struct ucred        sk_peercred;
    /* 
     * 套接字层接收超时，初始值为MAX_SCHEDULE_TIMEOUT。
     * 可以通过套接字选项SO_RCVTIMEO来设置接收的超时时间。 sock_init_data设置为无限大，也就是accept的时候默认是无限阻塞的，见inet_csk_accept
     * 如果想设置为非阻塞，可以通过SO_RCVTIMEO参数设置
     */
    long            sk_rcvtimeo;
    /* 
     * 套接字层发送超时,初始值为MAX_SCHEDULE_TIMEOUT。
     * 可以通过套接字选项SO_SNDTIMEO来设置发送的超时时间。 connect的时候判断是否connect超时用的就是这个值  使用该值的地方在sock_sndtimeo
     */
    long            sk_sndtimeo;
    /* 
     * 套接字过滤器。在传输层对输入的数据包通过BPF过滤代码进行过滤，
     * 只对设置了套接字过滤器的进程有效。
     */
    struct sk_filter        *sk_filter;
    /* 
     * 传输控制块存放私有数据的指针
     */
    void            *sk_protinfo;
    /*
     * 通过TCP的不同状态，来实现连接定时器、FIN_WAIT_2定时器(该定时器在TCP四次挥手过程中结束，见tcp_rcv_state_process)以及
     * TCP保活定时器，在tcp_keepalive_timer中实现
     * 定时器处理函数为tcp_keepalive_timer(),参见tcp_v4_init_sock()
     * 和tcp_init_xmit_timers()。
     */
    struct timer_list   sk_timer;//inet_csk_init_xmit_timers  sock_init_data
    /* 
     * 在未启用SOCK_RCVTSTAMP套接字选项时，记录报文接收数据到
     * 应用层的时间戳。在启用SOCK_RCVTSTAMP套接字选项时，接收
     * 数据到应用层的时间戳记录在SKB的tstamp中
     */
    ktime_t         sk_stamp;
    /* 指向对应套接字的指针 */
    struct socket       *sk_socket;
    /* RPC层存放私有数据的指针 ，IPv4中未使用 */
    void            *sk_user_data;
    /* 
     * 指向为本传输控制块最近一次分配的页面，通常
     * 是当前套接字发送队列中最后一个SKB的分片数据的
     * 最后一页，但在某种特殊的状态下也有可能不是(
     * 比如，在tcp_sendmsg中成功分配了页面，但复制数据失败了)。
     * 同时还用于区分系统的页面和主动分配的页面，如果是系统
     * 的页面，是不能在页面中做修改的，而如果是在发送过程
     * 中主动分配的页面，则可以对页面中的数据进行修改或添加，
     * 参见tcp_sendmsg.
     * 
     * sk_sndmsg_page和sk_sndmsg_off主要起缓存的作用，可以直接找到
     * 最后一个页面，然后尝试把数据追加到该页中，如果不行，则分配
     * 新页面，然后向新页复制数据，并更新sk_sndmsg_page和sk_sndmsg_off
     * 的值
     */////在tcp_sendmsg中开辟空间后，并复制，见里面的TCP_PAGE(sk) = page
    struct page     *sk_sndmsg_page;
    /*
     * 指向sk_write_queue队列中第一个未发送的结点，如果sk_send_head
     * 为空则表示发送队列是空的，发送队列上的报文已全部发送。
     */
    struct sk_buff      *sk_send_head; //表示sk_write_queue队列中还未调用dev_queue_xmit的最前面一个SKB的地方
    /* 
     * 表示数据尾端在最后一页分片内的页内偏移，
     * 新的数据可以直接从这个位置复制到该分片中
     */ //在tcp_sendmsg中开辟空间后，并复制，见里面的TCP_OFF(sk) = off + copy;
    __u32           sk_sndmsg_off;
    /* 标识有数据即将写入套接口，
     * 也就是有写数据的请求*/
    int         sk_write_pending;
#ifdef CONFIG_SECURITY
    /* 指向sk_security_struct结构，安全模块使用*/
    void            *sk_security;
#endif
    __u32           sk_mark;
    /* XXX 4 bytes hole on 64 bit */
    /*
     * 当传输控制块的状态发生变化时，唤醒哪些等待本套接字的进程。
     * 在创建套接字时初始化，IPv4中为sock_def_wakeup()  通常当传输 状态发生变化时调用
     */
    void            (*sk_state_change)(struct sock *sk);
    /*
     * 当有数据到达接收处理时，唤醒或发送信号通知准备读本套接字的
     * 进程。在创建套接字时被初始化，IPv4中为sock_def_readable()。如果
     * 是netlink套接字，则为netlink_data_ready()。 通常当传输控制块接收到数据包，存在可读的数据之后被调用
     */
    void            (*sk_data_ready)(struct sock *sk, int bytes); //内核创建netlink sock的时候，对应的是netlink_kernel_create->netlink_data_ready
    /*
     * 在发送缓存大小发生变化或套接字被释放时，唤醒因等待本套接字而
     * 处于睡眠状态的进程，包括sk_sleep队列以及fasync_list队列上的
     * 进程。创建套接字时初始化，IPv4中默认为sock_def_write_space(),
     * TCP中为sk_stream_write_space().   进程处于休眠状态的地方在sock_alloc_send_pskb里面的sock_wait_for_wmem
     */
    void            (*sk_write_space)(struct sock *sk); //该函数在释放SKB的时候执行，见sock_wfree sock_rfree
    /*
     * 报告错误的回调函数，如果等待该传输控制块的进程正在睡眠，
     * 则将其唤醒(例如MSG_ERRQUEUE).在创建套接字时被初始化，
     * IPv4中为sock_def_error_report(). 通常当传输控制块发生错误时被调用
     */
    void            (*sk_error_report)(struct sock *sk);
    /*
     * 用于TCP和PPPoE中。在TCP中，用于接收预备队列和后备队列中的
     * TCP段，TCP的sk_backlog_rcv接口为tcp_v4_do_rcv()。如果预备
     * 队列中还存在TCP段，则调用tcp_prequeue_process()预处理，在
     * 该函数中会回调sk_backlog_rcv()。如果后备队列中还存在TCP段，
     * 则调用release_sock()处理，也会回调sk_backlog_rcv()。该函数
     * 指针在创建套接字的传输控制块时由传输层backlog_rcv接口初始化
     */
    int         (*sk_backlog_rcv)(struct sock *sk,
                          struct sk_buff *skb);  
    /*
     * 进行传输控制块的销毁，在释放传输控制块前释放一些其他资源，在
     * sk_free()释放传输控制块时调用。当传输控制块的引用计数器为0时，
     * 才真正释放。IPv4中为inet_sock_destruct().
     */
    void                    (*sk_destruct)(struct sock *sk);
};


 //*struct sock是与具体传输层协议相关的套接字，所有内核的操作都基于这个套接字。
 //传输控制块  struct socket里面的struct sock指向了这里
 //在inet_create中为该结构体分配空间并赋初值。
 /*套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)*/
struct sock1 { 
	/*
	 * Now struct inet_timewait_sock also uses sock_common, so please just
	 * don't add nothing before this first member (__sk_common) --acme
	 */
	struct sock_common	__sk_common;
#define sk_node			__sk_common.skc_node
#define sk_nulls_node		__sk_common.skc_nulls_node
#define sk_refcnt		__sk_common.skc_refcnt
#define sk_tx_queue_mapping	__sk_common.skc_tx_queue_mapping

#define sk_copy_start		__sk_common.skc_hash
#define sk_hash			__sk_common.skc_hash
#define sk_family		__sk_common.skc_family
#define sk_state		__sk_common.skc_state
#define sk_reuse		__sk_common.skc_reuse
#define sk_bound_dev_if		__sk_common.skc_bound_dev_if
#define sk_bind_node		__sk_common.skc_bind_node
#define sk_prot			__sk_common.skc_prot//tcp_prot、udp_prot或者netlink_proto等  inet_create中赋值
#define sk_net			__sk_common.skc_net
	kmemcheck_bitfield_begin(flags);
	unsigned int		sk_shutdown  : 2,
				sk_no_check  : 2,
				sk_userlocks : 4,
				sk_protocol  : 8,//也就是应用层sock函数的第三个参数，表示协议类型，如果为netlink，也就是最大为32
				sk_type      : 16;
	kmemcheck_bitfield_end(flags);
	int			sk_rcvbuf;
	socket_lock_t		sk_lock;
	/*
	 * The backlog queue is special, it is always used with
	 * the per-socket spinlock held and requires low latency
	 * access. Therefore we special case it's implementation.
	 */
	struct {
		struct sk_buff *head;
		struct sk_buff *tail;
		int len;
	} sk_backlog;
	struct socket_wq	*sk_wq;
	struct dst_entry	*sk_dst_cache;
#ifdef CONFIG_XFRM
	struct xfrm_policy	*sk_policy[2];
#endif
	spinlock_t		sk_dst_lock;
	atomic_t		sk_rmem_alloc;
	atomic_t		sk_wmem_alloc;
	atomic_t		sk_omem_alloc;
	int			sk_sndbuf;
	struct sk_buff_head	sk_receive_queue;//应用层send的时候，会在内核开辟SKB空间，然后添加到该链表中
	struct sk_buff_head	sk_write_queue;
#ifdef CONFIG_NET_DMA
	struct sk_buff_head	sk_async_wait_queue;
#endif
	int			sk_wmem_queued;
	int			sk_forward_alloc;
	gfp_t			sk_allocation;
	int			sk_route_caps;
	int			sk_route_nocaps;
	int			sk_gso_type;
	unsigned int		sk_gso_max_size;
	int			sk_rcvlowat;
#ifdef CONFIG_RPS
	__u32			sk_rxhash;
#endif
	unsigned long 		sk_flags;
	unsigned long	        sk_lingertime;
	struct sk_buff_head	sk_error_queue; //icmp差错信息会添加到该链表中 参考樊东东P229 P230
	struct proto		*sk_prot_creator;
	rwlock_t		sk_callback_lock;
	int			sk_err,
				sk_err_soft;
	atomic_t		sk_drops;
	unsigned short		sk_ack_backlog;
	unsigned short		sk_max_ack_backlog;
	__u32			sk_priority;
	struct ucred		sk_peercred;
	long			sk_rcvtimeo;
	long			sk_sndtimeo;
	struct sk_filter      	*sk_filter;
	void			*sk_protinfo;
	struct timer_list	sk_timer;
	ktime_t			sk_stamp;
	struct socket		*sk_socket;
	void			*sk_user_data;
	struct page		*sk_sndmsg_page;
	struct sk_buff		*sk_send_head;
	__u32			sk_sndmsg_off;
	int			sk_write_pending;
#ifdef CONFIG_SECURITY
	void			*sk_security;
#endif
	__u32			sk_mark;
	u32			sk_classid;
	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk, int bytes);
	void			(*sk_write_space)(struct sock *sk);
	void			(*sk_error_report)(struct sock *sk);
  	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);  
	void                    (*sk_destruct)(struct sock *sk);
};

/*
 * Hashed lists helper routines
 */
static inline struct sock *sk_entry(const struct hlist_node *node)
{
	return hlist_entry(node, struct sock, sk_node);
}

static inline struct sock *__sk_head(const struct hlist_head *head)
{
	return hlist_entry(head->first, struct sock, sk_node);
}

static inline struct sock *sk_head(const struct hlist_head *head)
{
	return hlist_empty(head) ? NULL : __sk_head(head);
}

static inline struct sock *__sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_entry(head->first, struct sock, sk_nulls_node);
}

static inline struct sock *sk_nulls_head(const struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL : __sk_nulls_head(head);
}

static inline struct sock *sk_next(const struct sock *sk)
{
	return sk->sk_node.next ?
		hlist_entry(sk->sk_node.next, struct sock, sk_node) : NULL;
}

static inline struct sock *sk_nulls_next(const struct sock *sk)
{
	return (!is_a_nulls(sk->sk_nulls_node.next)) ?
		hlist_nulls_entry(sk->sk_nulls_node.next,
				  struct sock, sk_nulls_node) :
		NULL;
}

static inline int sk_unhashed(const struct sock *sk)
{
	return hlist_unhashed(&sk->sk_node);
}

static inline int sk_hashed(const struct sock *sk)
{
	return !sk_unhashed(sk);
}

static __inline__ void sk_node_init(struct hlist_node *node)
{
	node->pprev = NULL;
}

static __inline__ void sk_nulls_node_init(struct hlist_nulls_node *node)
{
	node->pprev = NULL;
}

static __inline__ void __sk_del_node(struct sock *sk)
{
	__hlist_del(&sk->sk_node);
}

/* NB: equivalent to hlist_del_init_rcu */
static __inline__ int __sk_del_node_init(struct sock *sk)
{
	if (sk_hashed(sk)) {
		__sk_del_node(sk);
		sk_node_init(&sk->sk_node);
		return 1;
	}
	return 0;
}

/* Grab socket reference count. This operation is valid only
   when sk is ALREADY grabbed f.e. it is found in hash table
   or a list and the lookup is made under lock preventing hash table
   modifications.
 */

static inline void sock_hold(struct sock *sk)
{
	atomic_inc(&sk->sk_refcnt);
}

/* Ungrab socket in the context, which assumes that socket refcnt
   cannot hit zero, f.e. it is true in context of any socketcall.
 */
static inline void __sock_put(struct sock *sk)
{
	atomic_dec(&sk->sk_refcnt);
}

static __inline__ int sk_del_node_init(struct sock *sk)
{
	int rc = __sk_del_node_init(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)

static __inline__ int __sk_nulls_del_node_init_rcu(struct sock *sk)
{
	if (sk_hashed(sk)) {
		hlist_nulls_del_init_rcu(&sk->sk_nulls_node);
		return 1;
	}
	return 0;
}

static __inline__ int sk_nulls_del_node_init_rcu(struct sock *sk)
{
	int rc = __sk_nulls_del_node_init_rcu(sk);

	if (rc) {
		/* paranoid for a while -acme */
		WARN_ON(atomic_read(&sk->sk_refcnt) == 1);
		__sock_put(sk);
	}
	return rc;
}

static __inline__ void __sk_add_node(struct sock *sk, struct hlist_head *list)
{
	hlist_add_head(&sk->sk_node, list);
}

static __inline__ void sk_add_node(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	__sk_add_node(sk, list);
}

static __inline__ void sk_add_node_rcu(struct sock *sk, struct hlist_head *list)
{
	sock_hold(sk);
	hlist_add_head_rcu(&sk->sk_node, list);
}

static __inline__ void __sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	hlist_nulls_add_head_rcu(&sk->sk_nulls_node, list);
}

static __inline__ void sk_nulls_add_node_rcu(struct sock *sk, struct hlist_nulls_head *list)
{
	sock_hold(sk);
	__sk_nulls_add_node_rcu(sk, list);
}

static __inline__ void __sk_del_bind_node(struct sock *sk)
{
	__hlist_del(&sk->sk_bind_node);
}

static __inline__ void sk_add_bind_node(struct sock *sk,
					struct hlist_head *list)
{
	hlist_add_head(&sk->sk_bind_node, list);
}

#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)
#define sk_for_each_rcu(__sk, node, list) \
	hlist_for_each_entry_rcu(__sk, node, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_from(__sk, node, sk_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_for_each_continue(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_continue(__sk, node, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
#define sk_for_each_bound(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_bind_node)

/* Sock flags */
enum sock_flags1 {
	SOCK_DEAD,
	SOCK_DONE,
	SOCK_URGINLINE,
	SOCK_KEEPOPEN,
	SOCK_LINGER,
	SOCK_DESTROY,
	SOCK_BROADCAST,
	SOCK_TIMESTAMP,
	SOCK_ZAPPED,
	SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
	SOCK_DBG, /* %SO_DEBUG setting */
	SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
	SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
	SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
	SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
	SOCK_TIMESTAMPING_TX_HARDWARE,  /* %SOF_TIMESTAMPING_TX_HARDWARE */
	SOCK_TIMESTAMPING_TX_SOFTWARE,  /* %SOF_TIMESTAMPING_TX_SOFTWARE */
	SOCK_TIMESTAMPING_RX_HARDWARE,  /* %SOF_TIMESTAMPING_RX_HARDWARE */
	SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
	SOCK_TIMESTAMPING_SOFTWARE,     /* %SOF_TIMESTAMPING_SOFTWARE */
	SOCK_TIMESTAMPING_RAW_HARDWARE, /* %SOF_TIMESTAMPING_RAW_HARDWARE */
	SOCK_TIMESTAMPING_SYS_HARDWARE, /* %SOF_TIMESTAMPING_SYS_HARDWARE */
	SOCK_FASYNC, /* fasync() active */
	SOCK_RXQ_OVFL,
};

/*

*/
    /* Sock flags */
    enum sock_flags {
        SOCK_DEAD, /* 连接已断开，套接字即将关闭  //tcp_close里面的sock_orphan执行这个*/
        SOCK_DONE, /* 标识TCP会话即将结束，在接收到FIN报文时设置*/
        SOCK_URGINLINE, /* 带外数据放入正常数据流，在普通数据流中接收带外数据*/
        SOCK_KEEPOPEN, /* 启用TCP传输层的保活定时*/
        /* 关闭套接字前发送剩余数据的时间，如果设置了该标记，应用层CLOSE的时候不会立马返回，
        会等待设置该标志的时候携带的等待时间后才返回，如果这个时间大于0，则会等待，等待过程中，缓冲区的数据就可以发送出去，
        如果等待时间为0，则直接删除未发送的数据，见inet_release   tcp_close*/
        SOCK_LINGER, 
        SOCK_DESTROY, /* 协议控制块已经释放，IPv4协议族未使用 */
        SOCK_BROADCAST, /* 套接口支持收发广播报文*/
        SOCK_TIMESTAMP, /* 标识是否启用段的接收时间作为时间戳*/
        SOCK_ZAPPED, /* 在ax25和ipx协议族中标识建立了连接。IPv4协议族未使用*/
        /* 
         * 标识是否初始化了传输控制块中的sk_write_space()指针，这样在
         * sock_wfree()中sk_write_space可以被调用
         */
        SOCK_USE_WRITE_QUEUE, /* whether to call sk->sk_write_space in sock_wfree */
        /* 记录套接字的调试信息*/
        SOCK_DBG, /* %SO_DEBUG setting */
        /* 数据包的接收时间作为时间戳*/
        SOCK_RCVTSTAMP, /* %SO_TIMESTAMP setting */
        SOCK_RCVTSTAMPNS, /* %SO_TIMESTAMPNS setting */
        /* 使用本地路由表还是策略路由表*/
        SOCK_LOCALROUTE, /* route locally only, %SO_DONTROUTE setting */
        /* 发送队列的缓存区最近是否缩小过 */
        SOCK_QUEUE_SHRUNK, /* write queue has been shrunk recently */
        SOCK_TIMESTAMPING_TX_HARDWARE,  /* %SOF_TIMESTAMPING_TX_HARDWARE */
        SOCK_TIMESTAMPING_TX_SOFTWARE,  /* %SOF_TIMESTAMPING_TX_SOFTWARE */
        SOCK_TIMESTAMPING_RX_HARDWARE,  /* %SOF_TIMESTAMPING_RX_HARDWARE */
        SOCK_TIMESTAMPING_RX_SOFTWARE,  /* %SOF_TIMESTAMPING_RX_SOFTWARE */
        SOCK_TIMESTAMPING_SOFTWARE,     /* %SOF_TIMESTAMPING_SOFTWARE */
        SOCK_TIMESTAMPING_RAW_HARDWARE, /* %SOF_TIMESTAMPING_RAW_HARDWARE */
        SOCK_TIMESTAMPING_SYS_HARDWARE, /* %SOF_TIMESTAMPING_SYS_HARDWARE */
    };

static inline void sock_copy_flags(struct sock *nsk, struct sock *osk)
{
	nsk->sk_flags = osk->sk_flags;
}

static inline void sock_set_flag(struct sock *sk, enum sock_flags flag)
{
	__set_bit(flag, &sk->sk_flags);
}

static inline void sock_reset_flag(struct sock *sk, enum sock_flags flag)
{
	__clear_bit(flag, &sk->sk_flags);
}

static inline int sock_flag(struct sock *sk, enum sock_flags flag)
{
	return test_bit(flag, &sk->sk_flags);
}
//在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
static inline void sk_acceptq_removed(struct sock *sk)
{
	sk->sk_ack_backlog--;
}

//在三次握手成功的第三步ACK成功后，会从listen_sock里面的syn_table hash中取出，让后加入到request_sock_queue的rskq_accept_head中，
//同时增加已连接成功值，当应用程序调用accept的时候，会从里面取出这个已连接信息，然后再减小改制，同时释放这个request_sock
static inline void sk_acceptq_added(struct sock *sk)
{
	sk->sk_ack_backlog++;
}

//sk_ack_backlog是已经完成了三次握手，但是还没有被accept系统调用处理的连接请求数量是否已经达到最大限制
static inline int sk_acceptq_is_full(struct sock *sk)
{
	return sk->sk_ack_backlog > sk->sk_max_ack_backlog;
}

/*
 * Compute minimal free write space needed to queue new packets.
 */
static inline int sk_stream_min_wspace(struct sock *sk)
{
	return sk->sk_wmem_queued >> 1;
}

static inline int sk_stream_wspace(struct sock *sk)
{
	return sk->sk_sndbuf - sk->sk_wmem_queued;
}

extern void sk_stream_write_space(struct sock *sk);

static inline int sk_stream_memory_free(struct sock *sk)
{
	return sk->sk_wmem_queued < sk->sk_sndbuf;
}

/* OOB backlog add */
static inline void __sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	/* dont let skb dst not refcounted, we are going to leave rcu lock */
	skb_dst_force(skb);

	if (!sk->sk_backlog.tail)
		sk->sk_backlog.head = skb;
	else
		sk->sk_backlog.tail->next = skb;

	sk->sk_backlog.tail = skb;
	skb->next = NULL;
}

/*
 * Take into account size of receive queue and backlog queue
 */
static inline bool sk_rcvqueues_full(const struct sock *sk, const struct sk_buff *skb)
{
	unsigned int qsize = sk->sk_backlog.len + atomic_read(&sk->sk_rmem_alloc);

	return qsize + skb->truesize > sk->sk_rcvbuf;
}

/* The per-socket spinlock must be held here. */
static inline __must_check int sk_add_backlog(struct sock *sk, struct sk_buff *skb)
{
	if (sk_rcvqueues_full(sk, skb))
		return -ENOBUFS;

	__sk_add_backlog(sk, skb);
	sk->sk_backlog.len += skb->truesize;
	return 0;
}

static inline int sk_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	return sk->sk_backlog_rcv(sk, skb);
}

static inline void sock_rps_record_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_record_sock_flow(sock_flow_table, sk->sk_rxhash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_reset_flow(const struct sock *sk)
{
#ifdef CONFIG_RPS
	struct rps_sock_flow_table *sock_flow_table;

	rcu_read_lock();
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	rps_reset_sock_flow(sock_flow_table, sk->sk_rxhash);
	rcu_read_unlock();
#endif
}

static inline void sock_rps_save_rxhash(struct sock *sk, u32 rxhash)
{
#ifdef CONFIG_RPS
	if (unlikely(sk->sk_rxhash != rxhash)) {
		sock_rps_reset_flow(sk);
		sk->sk_rxhash = rxhash;
	}
#endif
}

#define sk_wait_event(__sk, __timeo, __condition)			\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		}							\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

extern int sk_stream_wait_connect(struct sock *sk, long *timeo_p);
extern int sk_stream_wait_memory(struct sock *sk, long *timeo_p);
extern void sk_stream_wait_close(struct sock *sk, long timeo_p);
extern int sk_stream_error(struct sock *sk, int flags, int err);
extern void sk_stream_kill_queues(struct sock *sk);

extern int sk_wait_data(struct sock *sk, long *timeo);

struct request_sock_ops;
struct timewait_sock_ops;
struct inet_hashinfo;
struct raw_hashinfo;

/* Networking protocol blocks we attach to sockets.
 * socket layer -> transport layer interface
 * transport -> network interface is defined by struct inet_proto
 */ //网络层接口，对应tcp_prot  udp_prot  raw_prot
 //struct inet_protosw结构中有结构
struct proto {
	void			(*close)(struct sock *sk, 
					long timeout);
	int			(*connect)(struct sock *sk,
				        struct sockaddr *uaddr, 
					int addr_len);
	int			(*disconnect)(struct sock *sk, int flags);

	struct sock *		(*accept) (struct sock *sk, int flags, int *err);

	int			(*ioctl)(struct sock *sk, int cmd,
					 unsigned long arg);
	int			(*init)(struct sock *sk); /* 传输层初始化接口，在创建套接口时，在inet_create中调用 */
	void			(*destroy)(struct sock *sk); /* 关闭套接口的时候调用 */
	void			(*shutdown)(struct sock *sk, int how);
	int			(*setsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*getsockopt)(struct sock *sk, int level, 
					int optname, char __user *optval, 
					int __user *option);  	 
#ifdef CONFIG_COMPAT
	int			(*compat_setsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					unsigned int optlen);
	int			(*compat_getsockopt)(struct sock *sk,
					int level,
					int optname, char __user *optval,
					int __user *option);
#endif
	int			(*sendmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg, size_t len);
	int			(*recvmsg)(struct kiocb *iocb, struct sock *sk,
					   struct msghdr *msg,
					size_t len, int noblock, int flags, 
					int *addr_len);
	int			(*sendpage)(struct sock *sk, struct page *page,
					int offset, size_t size, int flags);
	int			(*bind)(struct sock *sk, 
					struct sockaddr *uaddr, int addr_len);


/* 引入这个后备队列的原因:例如TCP段接收过程中，如果传输控制块未被用户进程上锁，则将TCP段输入到接收队列中，否则接收到后备队列中,如果没有后备队列，如过用户进程在recv数据的时候，进入系统内核调度中执行，如果这时候驱动接收到数据
执行完硬件中断开始执行下半部的时候，如果直接用已有队列就会对共享内存数据造成影响*/
	int			(*backlog_rcv) (struct sock *sk, 
						struct sk_buff *skb); /* 用于接收预备队列和后备队列中的数据 */

    /* 
     * hash为添加到管理传输控制块散列表的接口，unhash为从管理传输控制块散列表中删除的接口。由于不同的传输层协议组织管理传输控制块也不一样，
     * 因此需要提供不同的方法，比如,在TCP中实现接口函数分别为inet_hash和inet_unhash。而UDP传输控制块的管理相对比较简单，只有绑定端口的传输
     * 控制块才会添加到散列表中，这由绑定过程来完成，因此不需要实现hash接口，只需实现unhash接口即可(2.6.32中是udp_lib_hash和udp_lib_unhash，
     参见udp_prot)
     */
	/* Keeping track of sk's, looking them up, and port selection methods. */
	void			(*hash)(struct sock *sk); //将该传输控制块socket添加到tcp_hashinfo的ehash中
	void			(*unhash)(struct sock *sk);
	void			(*rehash)(struct sock *sk);

/*
 * 实现地址与端口的绑定。参数sk为进行绑定操作的传输控制块，snum为进行绑定的端口号(如果为0，端口号在绑定时自动选择)。TCP中为 inet_csk_get_port,UDP中为udp_v4_get_port。
 */
	int			(*get_port)(struct sock *sk, unsigned short snum);

	/* Keeping track of sockets in use */
#ifdef CONFIG_PROC_FS
	unsigned int		inuse_idx;
#endif

    /*
     * 目前只有TCP使用，当前整个TCP传输层中为缓冲区分配的内存超过tcp_mem[1]，便进入了警告状态，会调用此接口设置警告状态。在TCP中它指向tcp_enter_memory_pressure.
     */
	/* Memory pressure */
	void			(*enter_memory_pressure)(struct sock *sk);

	/*
     * 目前只有TCP使用，表示当前整个TCP传输层中为缓冲区分配的内存 (包括输入缓冲队列)。在TCP中它指向变量tcp_memory_allocated
     * 
     * update:如果是TCP层，它指向变量tcp_memory_allocated，表示当前整个TCP传输层为缓冲区分配的内存页面数，是系统中
     * 所有TCP传输块的sk_forward_alloc的总和，并不是所有传输控制块的发送和接收缓冲区综合，切记!
     */
     /*
 * 无论是为发送而分配SKB，还是将报文接收到TCP
 * 传输层，都需要对新进入传输控制块的缓存进行
 * 确认。确认时如果套接字缓存中的数据长度大于
 * 预分配量，则需进行全面的确认，这个过程由
 * __sk_mem_schedule()实现。
 * @size:要确认的缓存长度
 * @kind:类型，0为发送缓存，1为接收缓存。
 */
     ////当tcp_memory_allocated大于sysctl_tcp_mem[1]时，TCP缓存管理进入警告状态，tcp_memory_pressure置为1。 这几个变量存到proto中的对应变量中。
//当tcp_memory_allocated小于sysctl_tcp_mem[0]时，TCP缓存管理退出警告状态，tcp_memory_pressure置为0。 
	atomic_t		*memory_allocated;	/* Current allocated memory. */  //见__sk_mem_schedule

	/*
     * 表示当前整个TCP传输层中已创建的套接字的数目。目前只在TCP中使用，它指向变量tcp_sockets_allocated
     */
	struct percpu_counter	*sockets_allocated;	/* Current number of sockets. */
	/*
	 * Pressure flag: try to collapse.
	 * Technical note: it is used by multiple contexts non atomically.
	 * All the __sk_mem_schedule() is of this nature: accounting
	 * is strict, actions are advisory and have some latency.
	 */
	/*
	 * 目前只有TCP使用，在TCP传输层中缓冲大小进入警告状态时，它置为1，
	 * 否则置为0.目前只在TCP中使用，它指向变量tcp_memory_pressure.
	 */
	 ////当tcp_memory_allocated大于tcp_mem[1]时，TCP缓存管理进入警告状态，tcp_memory_pressure置为1。 这几个变量存到proto中的对应变量中。
//当tcp_memory_allocated小于tcp_mem[0]时，TCP缓存管理退出警告状态，tcp_memory_pressure置为0。 
////阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*memory_pressure;
    /* 指向sysctl_tcp_mem数组，参见sysctl_tcp_mem系统参数 */
    ////阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*sysctl_mem;
    /* 指向sysctl_tcp_wmem数组，参见sysctl_tcp_wmem系统参数 */
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*sysctl_wmem;
    /* 指向sysctl_tcp_rmem数组，参见sysctl_tcp_rmem系统参数 */
    //阅读函数__sk_mem_schedule可以了解proto的内存情况判断方法
	int			*sysctl_rmem;
    /* 目前只有TCP使用，TCP首部的最大长度，考虑了所有的选项  值为MAX_TCP_HEADER*/
	int			max_header;

    /* 用于分配传输控制块的slab高速缓存，在注册对应传输层协议时建立 */
	struct kmem_cache	*slab;

	
	 /*
     * 标识传输控制块的大小，如果在初始化时建立分配传输控制块的slab
     * 缓存失败，则通过kmalloc分配obj_size大小的空间来完成传输控制
     * 块的分配。见inet_init中的proto_register
     */
	unsigned int		obj_size;
	int			slab_flags;

     /*
     * 目前只在TCP中使用，表示整个TCP传输层中待销毁的套接字的数目。在TCP中，它指向变量tcp_orphan_count.
     *///在tcp_close的时候要判断这个值是否超过阀值sysctl_tcp_max_orphans，见tcp_too_many_orphans
	struct percpu_counter	*orphan_count;

    /*
     * 目前只在TCP中使用，指向连接请求处理接口集合，包括 发送SYN+ACK等实现
     */
	struct request_sock_ops	*rsk_prot;

	/*
     * 目前只在TCP中使用，指向timewait控制块操作接口，TCP中的实例为tcp_timewait_sock_ops.timewait_sock_ops结构提供
     * 了两个操作接口，tcp_twsk_unique()用于检测被timewait控制块绑定的端口是否可用，而tcp_twsk_destructor用于在释放
     * timewait控制块时，在启用MD5数字签名的情况下做一些清理工作
     */
	struct timewait_sock_ops *twsk_prot;

	union {
		struct inet_hashinfo	*hashinfo; //tcp_hashinfo
		struct udp_table	*udp_table; //udp_table
		struct raw_hashinfo	*raw_hash; //raw_v4_hashinfo
	} h;

	struct module		*owner;

    /* 标识传输层的名称，TCP协议为"TCP",UDP协议则为"UDP" */
	char			name[32];

    /* 通过node注册到proto_list中 */
	struct list_head	node;
#ifdef SOCK_REFCNT_DEBUG
	atomic_t		socks;
#endif
};

extern int proto_register(struct proto *prot, int alloc_slab);
extern void proto_unregister(struct proto *prot);

#ifdef SOCK_REFCNT_DEBUG
static inline void sk_refcnt_debug_inc(struct sock *sk)
{
	atomic_inc(&sk->sk_prot->socks);
}

static inline void sk_refcnt_debug_dec(struct sock *sk)
{
	atomic_dec(&sk->sk_prot->socks);
	printk(KERN_DEBUG "%s socket %p released, %d are still alive\n",
	       sk->sk_prot->name, sk, atomic_read(&sk->sk_prot->socks));
}

static inline void sk_refcnt_debug_release(const struct sock *sk)
{
	if (atomic_read(&sk->sk_refcnt) != 1)
		printk(KERN_DEBUG "Destruction of the %s socket %p delayed, refcnt=%d\n",
		       sk->sk_prot->name, sk, atomic_read(&sk->sk_refcnt));
}
#else /* SOCK_REFCNT_DEBUG */
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#endif /* SOCK_REFCNT_DEBUG */


#ifdef CONFIG_PROC_FS
/* Called with local bh disabled */
extern void sock_prot_inuse_add(struct net *net, struct proto *prot, int inc);
extern int sock_prot_inuse_get(struct net *net, struct proto *proto);
#else
static void inline sock_prot_inuse_add(struct net *net, struct proto *prot,
		int inc)
{
}
#endif


/* With per-bucket locks this operation is not-atomic, so that
 * this version is not worse.
 */
static inline void __sk_prot_rehash(struct sock *sk)
{
	sk->sk_prot->unhash(sk);
	sk->sk_prot->hash(sk);
}

/* About 10 seconds */
#define SOCK_DESTROY_TIME (10*HZ)

/* Sockets 0-1023 can't be bound to unless you are superuser */
#define PROT_SOCK	1024

/* 表示完全关闭 */
#define SHUTDOWN_MASK	3  //tcp_close应用程序调用close肯定是完全关闭，如果是shutdown则可选半关闭还是完全关闭
/* 接收通道关闭，不允许继续接收数据*/
#define RCV_SHUTDOWN	1
/* 发送通道关闭，不允许继续发送数据*/
#define SEND_SHUTDOWN	2


#define SOCK_SNDBUF_LOCK	1
#define SOCK_RCVBUF_LOCK	2
#define SOCK_BINDADDR_LOCK	4
#define SOCK_BINDPORT_LOCK	8

/* sock_iocb: used to kick off async processing of socket ios */
struct sock_iocb {
	struct list_head	list;

	int			flags;
	int			size;
	struct socket		*sock;
	struct sock		*sk;
	struct scm_cookie	*scm;
	struct msghdr		*msg, async_msg;
	struct kiocb		*kiocb;
};

static inline struct sock_iocb *kiocb_to_siocb(struct kiocb *iocb)
{
	return (struct sock_iocb *)iocb->private;
}

static inline struct kiocb *siocb_to_kiocb(struct sock_iocb *si)
{
	return si->kiocb;
}
/*
套接口文件系统inode结点和套接口是一一对应的，因此套接口文件系统的i结点和分配是比较特殊的，分配的并不是一个单纯的i结点，而是i结点和
socket结构的组合体，即socket_calloc结构，这样可以使套接口的分配及与之绑定的套接口文件的i结点的分配同时进行。在应用层访问套接口要通过文件描述符
，这样就可以快速地通过文件描述符定位与之绑定的套接口。
*/
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}

static inline struct inode *SOCK_INODE(struct socket *socket)
{
	return &container_of(socket, struct socket_alloc, socket)->vfs_inode;
}

/*
 * Functions for memory accounting
 */
extern int __sk_mem_schedule(struct sock *sk, int size, int kind);
extern void __sk_mem_reclaim(struct sock *sk);

#define SK_MEM_QUANTUM ((int)PAGE_SIZE)
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SK_MEM_SEND	0
#define SK_MEM_RECV	1

static inline int sk_mem_pages(int amt)
{
	return (amt + SK_MEM_QUANTUM - 1) >> SK_MEM_QUANTUM_SHIFT;
}

static inline int sk_has_account(struct sock *sk)
{
	/* return true if protocol supports memory accounting */
	return !!sk->sk_prot->memory_allocated;
}

static inline int sk_wmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return 1;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_SEND);
}

static inline int sk_rmem_schedule(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return 1;
	return size <= sk->sk_forward_alloc ||
		__sk_mem_schedule(sk, size, SK_MEM_RECV);
}

/*
 * 在多种情况下会调用sk_mem_reclaim()来回收缓存，如在
 * 断开连接、释放传输控制块、关闭TCP套接字时释放
 * 发送或接收队列中的SKB。sk_mem_reclaim()只在预分配量
 * 大于一个页面时，才调用__sk_mem_reclaim()进行真正的
 * 缓存回收。
 */
static inline void sk_mem_reclaim(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc >= SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}

static inline void sk_mem_reclaim_partial(struct sock *sk)
{
	if (!sk_has_account(sk))
		return;
	if (sk->sk_forward_alloc > SK_MEM_QUANTUM)
		__sk_mem_reclaim(sk);
}
//skb_entail会把skb添加到sk的发送队列尾部，然后调用sk_mem_charge调整sk_wmem_quequed和sk_forward_alloc。前则将增加该skb中数据的长度，而后则则减少该skb中数据的长度
//在发送时会调用skb_set_owner_w设置该skb的宿主，同时设置释放是的回调函数为sock_wfree，最后sk_wmem_alloc将增加该skb中数据的长度。
static inline void sk_mem_charge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc -= size;
}

static inline void sk_mem_uncharge(struct sock *sk, int size)
{
	if (!sk_has_account(sk))
		return;
	sk->sk_forward_alloc += size;
}

static inline void sk_wmem_free_skb(struct sock *sk, struct sk_buff *skb)
{
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	sk->sk_wmem_queued -= skb->truesize;
	sk_mem_uncharge(sk, skb->truesize);
	__kfree_skb(skb);
}

/* Used by processes to "lock" a socket state, so that
 * interrupts and bottom half handlers won't change it
 * from under us. It essentially blocks any incoming
 * packets, so that we won't get any new data or any
 * packets that change the state of the socket.
 *
 * While locked, BH processing will add new packets to
 * the backlog queue.  This queue is processed by the
 * owner of the socket lock right before it is released.
 *
 * Since ~2.3.5 it is also exclusive sleep lock serializing
 * accesses from user process context.
 */
 
/*
 * 软中断在访问传输控制块时需要通过sock_owned_by_user
 * 宏来检测该控制块是否已经被进程锁定，如果没有
 * 锁定，则可直接访问而无需通过lock_sock来上锁。因为
 * 软中断的优先级比进程的优先级高得多，只有软中断
 * 能中断进程的执行，而进程决不能中断软中断的执行。
 * 例如，在TCP段接收过程中，如果传输控制块未被用户
 * 进程上锁，则将TCP段输入到接收队列中，否则接收
 * 到后备队列中        内核调度优先级参考:http://blog.csdn.net/allen6268198/article/details/7567679
 */
#define sock_owned_by_user(sk)	((sk)->sk_lock.owned)

/*
 * Macro so as to not evaluate some arguments when
 * lockdep is not enabled.
 *
 * Mark both the sk_lock and the sk_lock.slock as a
 * per-address-family lock class.
 */
#define sock_lock_init_class_and_name(sk, sname, skey, name, key) 	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
		       	(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)

extern void lock_sock_nested(struct sock *sk, int subclass);

/*
 * 用于进程加锁传输控制块，当进程调用网络相关的
 * 系统调用时，在访问传输控制块之前都会调用此函数，
 * 加锁传输控制块。
 * 注意这里在lock_sock_nested()中只是先获取了自旋锁，然后设置owned成员
 * 表示当前传输块被用户进程锁定，然后又释放了自旋锁。所以在
 * 软中断处理中(例如tcp_v4_rcv())会先获取锁，然后检查owned成员是否设置
 * 即传输控制块是否被用户进程锁定。
 */

/*
 * 实现控制用户进程和下半部 (例如应用程序发送数据的时候，然后进入系统调度到内核部分，这时候，内核又收到了对方来的数据，就好产生硬件中断，硬件中断上半部执行完后，执行下半部的时候就会用到刚才被抢走的发送数据的sock，从而会访问相同的数据空间，所以需要枷锁)
 以及下半部之间(例如多核环境下，内核硬件中断接收数据后进入软中断处理过程中，又收到了对方来的数据产生中断。)
 * 间同步锁都是由socket_lock_t结构描述的
 */
static inline void lock_sock(struct sock *sk)
{
	lock_sock_nested(sk, 0);
}

extern void release_sock(struct sock *sk);

/* BH context may only use the following locking interface. */
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))

extern bool lock_sock_fast(struct sock *sk);
/**
 * unlock_sock_fast - complement of lock_sock_fast
 * @sk: socket
 * @slow: slow mode
 *
 * fast unlock socket for user context.
 * If slow mode is on, we call regular release_sock()
 */
static inline void unlock_sock_fast(struct sock *sk, bool slow)
{
	if (slow)
		release_sock(sk);
	else
		spin_unlock_bh(&sk->sk_lock.slock);
}


extern struct sock		*sk_alloc(struct net *net, int family,
					  gfp_t priority,
					  struct proto *prot);
extern void			sk_free(struct sock *sk);
extern void			sk_release_kernel(struct sock *sk);
extern struct sock		*sk_clone(const struct sock *sk,
					  const gfp_t priority);

extern struct sk_buff		*sock_wmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern struct sk_buff		*sock_rmalloc(struct sock *sk,
					      unsigned long size, int force,
					      gfp_t priority);
extern void			sock_wfree(struct sk_buff *skb);
extern void			sock_rfree(struct sk_buff *skb);

extern int			sock_setsockopt(struct socket *sock, int level,
						int op, char __user *optval,
						unsigned int optlen);

extern int			sock_getsockopt(struct socket *sock, int level,
						int op, char __user *optval, 
						int __user *optlen);
extern struct sk_buff 		*sock_alloc_send_skb(struct sock *sk,
						     unsigned long size,
						     int noblock,
						     int *errcode);
extern struct sk_buff 		*sock_alloc_send_pskb(struct sock *sk,
						      unsigned long header_len,
						      unsigned long data_len,
						      int noblock,
						      int *errcode);
extern void *sock_kmalloc(struct sock *sk, int size,
			  gfp_t priority);
extern void sock_kfree_s(struct sock *sk, void *mem, int size);
extern void sk_send_sigurg(struct sock *sk);

#ifdef CONFIG_CGROUPS
extern void sock_update_classid(struct sock *sk);
#else
static inline void sock_update_classid(struct sock *sk)
{
}
#endif

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * does not implement a particular function.
 */
extern int                      sock_no_bind(struct socket *, 
					     struct sockaddr *, int);
extern int                      sock_no_connect(struct socket *,
						struct sockaddr *, int, int);
extern int                      sock_no_socketpair(struct socket *,
						   struct socket *);
extern int                      sock_no_accept(struct socket *,
					       struct socket *, int);
extern int                      sock_no_getname(struct socket *,
						struct sockaddr *, int *, int);
extern unsigned int             sock_no_poll(struct file *, struct socket *,
					     struct poll_table_struct *);
extern int                      sock_no_ioctl(struct socket *, unsigned int,
					      unsigned long);
extern int			sock_no_listen(struct socket *, int);
extern int                      sock_no_shutdown(struct socket *, int);
extern int			sock_no_getsockopt(struct socket *, int , int,
						   char __user *, int __user *);
extern int			sock_no_setsockopt(struct socket *, int, int,
						   char __user *, unsigned int);
extern int                      sock_no_sendmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t);
extern int                      sock_no_recvmsg(struct kiocb *, struct socket *,
						struct msghdr *, size_t, int);
extern int			sock_no_mmap(struct file *file,
					     struct socket *sock,
					     struct vm_area_struct *vma);
extern ssize_t			sock_no_sendpage(struct socket *sock,
						struct page *page,
						int offset, size_t size, 
						int flags);

/*
 * Functions to fill in entries in struct proto_ops when a protocol
 * uses the inet style.
 */
extern int sock_common_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen);
extern int sock_common_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t size, int flags);
extern int sock_common_setsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, unsigned int optlen);
extern int compat_sock_common_getsockopt(struct socket *sock, int level,
		int optname, char __user *optval, int __user *optlen);
extern int compat_sock_common_setsockopt(struct socket *sock, int level,
		int optname, char __user *optval, unsigned int optlen);

extern void sk_common_release(struct sock *sk);

/*
 *	Default socket callbacks and setup code
 */
 
/* Initialise core socket variables */
extern void sock_init_data(struct socket *sock, struct sock *sk);

extern void sk_filter_release_rcu(struct rcu_head *rcu);

/**
 *	sk_filter_release - release a socket filter
 *	@fp: filter to remove
 *
 *	Remove a filter from a socket and release its resources.
 */

static inline void sk_filter_release(struct sk_filter *fp)
{
	if (atomic_dec_and_test(&fp->refcnt))
		call_rcu_bh(&fp->rcu, sk_filter_release_rcu);
}

static inline void sk_filter_uncharge(struct sock *sk, struct sk_filter *fp)
{
	unsigned int size = sk_filter_len(fp);

	atomic_sub(size, &sk->sk_omem_alloc);
	sk_filter_release(fp);
}

static inline void sk_filter_charge(struct sock *sk, struct sk_filter *fp)
{
	atomic_inc(&fp->refcnt);
	atomic_add(sk_filter_len(fp), &sk->sk_omem_alloc);
}

/*
 * Socket reference counting postulates.
 *
 * * Each user of socket SHOULD hold a reference count.
 * * Each access point to socket (an hash table bucket, reference from a list,
 *   running timer, skb in flight MUST hold a reference count.
 * * When reference count hits 0, it means it will never increase back.
 * * When reference count hits 0, it means that no references from
 *   outside exist to this socket and current process on current CPU
 *   is last user and may/should destroy this socket.
 * * sk_free is called from any context: process, BH, IRQ. When
 *   it is called, socket has no references from outside -> sk_free
 *   may release descendant resources allocated by the socket, but
 *   to the time when it is called, socket is NOT referenced by any
 *   hash tables, lists etc.
 * * Packets, delivered from outside (from network or from another process)
 *   and enqueued on receive/error queues SHOULD NOT grab reference count,
 *   when they sit in queue. Otherwise, packets will leak to hole, when
 *   socket is looked up by one cpu and unhasing is made by another CPU.
 *   It is true for udp/raw, netlink (leak to receive and error queues), tcp
 *   (leak to backlog). Packet socket does all the processing inside
 *   BR_NETPROTO_LOCK, so that it has not this race condition. UNIX sockets
 *   use separate SMP lock, so that they are prone too.
 */

/* Ungrab socket and destroy it, if it was the last reference. */
static inline void sock_put(struct sock *sk)
{
	if (atomic_dec_and_test(&sk->sk_refcnt))
		sk_free(sk);
}

extern int sk_receive_skb(struct sock *sk, struct sk_buff *skb,
			  const int nested);

static inline void sk_tx_queue_set(struct sock *sk, int tx_queue)
{
	sk->sk_tx_queue_mapping = tx_queue;
}

static inline void sk_tx_queue_clear(struct sock *sk)
{
	sk->sk_tx_queue_mapping = -1;
}

static inline int sk_tx_queue_get(const struct sock *sk)
{
	return sk ? sk->sk_tx_queue_mapping : -1;
}

static inline void sk_set_socket(struct sock *sk, struct socket *sock)
{
	sk_tx_queue_clear(sk);
	sk->sk_socket = sock;
}

static inline wait_queue_head_t *sk_sleep(struct sock *sk)
{
	return &sk->sk_wq->wait;
}
/* Detach socket from process context.
 * Announce socket dead, detach it from wait queue and inode.
 * Note that parent inode held reference count on this struct sock,
 * we do not release it in this function, because protocol
 * probably wants some additional cleanups or even continuing
 * to work with this socket (TCP).
 *///tcp_close里面执行这个
static inline void sock_orphan(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sock_set_flag(sk, SOCK_DEAD);
	sk_set_socket(sk, NULL);
	sk->sk_wq  = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(sk->sk_wq, parent->wq);
	parent->sk = sk;
	sk_set_socket(sk, parent);
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}

extern int sock_i_uid(struct sock *sk);
extern unsigned long sock_i_ino(struct sock *sk);

static inline struct dst_entry *
__sk_dst_get(struct sock *sk)
{
	return rcu_dereference_check(sk->sk_dst_cache, rcu_read_lock_held() ||
						       sock_owned_by_user(sk) ||
						       lockdep_is_held(&sk->sk_lock.slock));
}

static inline struct dst_entry *
sk_dst_get(struct sock *sk)
{
	struct dst_entry *dst;

	rcu_read_lock();
	dst = rcu_dereference(sk->sk_dst_cache);
	if (dst)
		dst_hold(dst);
	rcu_read_unlock();
	return dst;
}

extern void sk_reset_txq(struct sock *sk);

static inline void dst_negative_advice(struct sock *sk)
{
	struct dst_entry *ndst, *dst = __sk_dst_get(sk);

	if (dst && dst->ops->negative_advice) {
		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_reset_txq(sk);
		}
	}
}

static inline void
__sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	struct dst_entry *old_dst;

	sk_tx_queue_clear(sk);
	/*
	 * This can be called while sk is owned by the caller only,
	 * with no state that can be checked in a rcu_dereference_check() cond
	 */
	old_dst = rcu_dereference_raw(sk->sk_dst_cache);
	rcu_assign_pointer(sk->sk_dst_cache, dst);
	dst_release(old_dst);
}

static inline void
sk_dst_set(struct sock *sk, struct dst_entry *dst)
{
	spin_lock(&sk->sk_dst_lock);
	__sk_dst_set(sk, dst);
	spin_unlock(&sk->sk_dst_lock);
}

static inline void
__sk_dst_reset(struct sock *sk)
{
	__sk_dst_set(sk, NULL);
}

static inline void
sk_dst_reset(struct sock *sk)
{
	spin_lock(&sk->sk_dst_lock);
	__sk_dst_reset(sk);
	spin_unlock(&sk->sk_dst_lock);
}

extern struct dst_entry *__sk_dst_check(struct sock *sk, u32 cookie);

extern struct dst_entry *sk_dst_check(struct sock *sk, u32 cookie);

////TSO是tcp segment offload的缩写，GSO是 generic segmentation offload 的缩写。 通过命令ethtool -k eth0查看是否支持gso或者tso 。参考skb_shared_info
static inline int sk_can_gso(const struct sock *sk)
{
	return net_gso_ok(sk->sk_route_caps, sk->sk_gso_type);
}

extern void sk_setup_caps(struct sock *sk, struct dst_entry *dst);

static inline void sk_nocaps_add(struct sock *sk, int flags)
{
	sk->sk_route_nocaps |= flags;
	sk->sk_route_caps &= ~flags;
}

static inline int skb_copy_to_page(struct sock *sk, char __user *from,
				   struct sk_buff *skb, struct page *page,
				   int off, int copy)
{
	if (skb->ip_summed == CHECKSUM_NONE) {
		int err = 0;
		__wsum csum = csum_and_copy_from_user(from,
						     page_address(page) + off,
							    copy, 0, &err);
		if (err)
			return err;
		skb->csum = csum_block_add(skb->csum, csum, skb->len);
	} else if (copy_from_user(page_address(page) + off, from, copy))
		return -EFAULT;

	skb->len	     += copy;
	skb->data_len	     += copy;
	skb->truesize	     += copy;
	sk->sk_wmem_queued   += copy;
	sk_mem_charge(sk, copy);
	return 0;
}

/**
 * sk_wmem_alloc_get - returns write allocations
 * @sk: socket
 *
 * Returns sk_wmem_alloc minus initial offset of one
 */
static inline int sk_wmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_wmem_alloc) - 1;
}

/**
 * sk_rmem_alloc_get - returns read allocations
 * @sk: socket
 *
 * Returns sk_rmem_alloc
 */
static inline int sk_rmem_alloc_get(const struct sock *sk)
{
	return atomic_read(&sk->sk_rmem_alloc);
}

/**
 * sk_has_allocations - check if allocations are outstanding
 * @sk: socket
 *
 * Returns true if socket has write or read allocations
 */
static inline int sk_has_allocations(const struct sock *sk)
{
	return sk_wmem_alloc_get(sk) || sk_rmem_alloc_get(sk);
}

/**
 * wq_has_sleeper - check if there are any waiting processes
 * @wq: struct socket_wq
 *
 * Returns true if socket_wq has waiting processes
 *
 * The purpose of the wq_has_sleeper and sock_poll_wait is to wrap the memory
 * barrier call. They were added due to the race found within the tcp code.
 *
 * Consider following tcp code paths:
 *
 * CPU1                  CPU2
 *
 * sys_select            receive packet
 *   ...                 ...
 *   __add_wait_queue    update tp->rcv_nxt
 *   ...                 ...
 *   tp->rcv_nxt check   sock_def_readable
 *   ...                 {
 *   schedule               rcu_read_lock();
 *                          wq = rcu_dereference(sk->sk_wq);
 *                          if (wq && waitqueue_active(&wq->wait))
 *                              wake_up_interruptible(&wq->wait)
 *                          ...
 *                       }
 *
 * The race for tcp fires when the __add_wait_queue changes done by CPU1 stay
 * in its cache, and so does the tp->rcv_nxt update on CPU2 side.  The CPU1
 * could then endup calling schedule and sleep forever if there are no more
 * data on the socket.
 *
 */
static inline bool wq_has_sleeper(struct socket_wq *wq)
{

	/*
	 * We need to be sure we are in sync with the
	 * add_wait_queue modifications to the wait queue.
	 *
	 * This memory barrier is paired in the sock_poll_wait.
	 */
	smp_mb();
	return wq && waitqueue_active(&wq->wait);
}

/**
 * sock_poll_wait - place memory barrier behind the poll_wait call.
 * @filp:           file
 * @wait_address:   socket wait queue
 * @p:              poll_table
 *
 * See the comments in the wq_has_sleeper function.
 */
static inline void sock_poll_wait(struct file *filp,
		wait_queue_head_t *wait_address, poll_table *p)
{
	if (p && wait_address) {
		poll_wait(filp, wait_address, p);
		/*
		 * We need to be sure we are in sync with the
		 * socket flags modification.
		 *
		 * This memory barrier is paired in the wq_has_sleeper.
		*/
		smp_mb();
	}
}

/*
 * 	Queue a received datagram if it will fit. Stream and sequenced
 *	protocols can't normally use this as they need to fit buffers in
 *	and play with them.
 *
 * 	Inlined as it's very short and called for pretty much every
 *	packet ever received.
 */
/* 
 * 每个用于输出的SKB都要关联到一个传输控制块上，
 * 这样可以调整该传输控制块为发送而分配的所有
 * SKB数据区的总大小，并设置此SKB的销毁函数。
 */
 //套接字发送数据的时候，struct sock和SKB的关系可以通过sock_alloc_send_pskb(UDP和RAW套接字用这个)函数详细了解。TCP在构造SYN+ACK时使用sock_wmalloc，发送用户数据时通常使用sk_stream_alloc_skb()分配发送缓存
//TCP在连接建立后发送数据的时候在tcp_transmit_skb中调用该函数，而在TCP构造过程中通过sock_wmalloc调用该函数，UDP和RAW则在sock_alloc_send_pskb中调用该函数

//skb_entail会把skb添加到sk的发送队列尾部，然后调用sk_mem_charge调整sk_wmem_quequed和sk_forward_alloc。前则将增加该skb中数据的长度，而后则则减少该skb中数据的长度
//在发送时会调用skb_set_owner_w设置该skb的宿主，同时设置释放是的回调函数为sock_wfree，最后sk_wmem_alloc将增加该skb中数据的长度。
static inline void skb_set_owner_w(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_wfree; ////在sk_alloc的时候初始化设置为1，然后在skb_set_owner_w加上SKB长度，当SKB发送出去后，在减去该SKB的长度，所以这个值当数据发送后其值始终是1，不会执行sock_wfree
	/*
	 * We used to take a refcount on sk, but following operation
	 * is enough to guarantee sk_free() wont free this sock until
	 * all in-flight packets are completed
	 */
	atomic_add(skb->truesize, &sk->sk_wmem_alloc);
}

/*
 * 当TCP段的SKB传递到TCP传输控制块中，便会调用
 * sk_stream_set_owner_r()设置该SKB的宿主，并设置此SKB
 * 的销毁函数，还要更新接收队列中所有报文数据
 * 的总长度，以及预分配缓存长度
 */
static inline void skb_set_owner_r(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rfree;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, skb->truesize);
}

extern void sk_reset_timer(struct sock *sk, struct timer_list* timer,
			   unsigned long expires);

extern void sk_stop_timer(struct sock *sk, struct timer_list* timer);

extern int sock_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);

extern int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb);

/*
 *	Recover an error report and clear atomically
 */
 
static inline int sock_error(struct sock *sk)
{
	int err;
	if (likely(!sk->sk_err))
		return 0;
	err = xchg(&sk->sk_err, 0);
	return -err;
}

static inline unsigned long sock_wspace(struct sock *sk)
{
	int amt = 0;

	if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
		amt = sk->sk_sndbuf - atomic_read(&sk->sk_wmem_alloc);
		if (amt < 0) 
			amt = 0;
	}
	return amt;
}

/*
 * 用来将SIGIO或SIGURG信号发送给该套接字上的进程，
 * 通知该进程可以对该文件进行读或写。
 *
 * @sk: 通知进程可运行I/O处理的传输控制块
 * @how: 通知进程方式，取值为SOCK_WAKE_IO等
 * @band:  通知进程的I/O读写类型，取值为POLL_IN等
 */

//执行该函数sk_wake_async(将SIGIO或SIGURG信号发送给该套接字上的进程,这是异步I/O机制)的地方有sk_send_sigurg(接收到带外数据)，sock_def_write_space和sk_stream_write_space(发送缓冲区发生变化)，有新的数据到来(sock_def_readable)
//sock_def_error_report传输控制块发生某种错误，sock_def_wakeup传输状态发生变化, tcp_fin
static inline void sk_wake_async(struct sock *sk, int how, int band)
{
	if (sock_flag(sk, SOCK_FASYNC))
		sock_wake_async(sk->sk_socket, how, band);
}

#define SOCK_MIN_SNDBUF 2048
#define SOCK_MIN_RCVBUF 256

static inline void sk_stream_moderate_sndbuf(struct sock *sk)
{
	if (!(sk->sk_userlocks & SOCK_SNDBUF_LOCK)) {
		sk->sk_sndbuf = min(sk->sk_sndbuf, sk->sk_wmem_queued >> 1);
		sk->sk_sndbuf = max(sk->sk_sndbuf, SOCK_MIN_SNDBUF);
	}
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp);

static inline struct page *sk_stream_alloc_page(struct sock *sk)
{
	struct page *page = NULL;

	page = alloc_pages(sk->sk_allocation, 0);
	if (!page) {
		sk->sk_prot->enter_memory_pressure(sk);
		sk_stream_moderate_sndbuf(sk);
	}
	return page;
}

/*
 *	Default write policy as shown to user space via poll/select/SIGIO
 */
static inline int sock_writeable(const struct sock *sk) 
{
	return atomic_read(&sk->sk_wmem_alloc) < (sk->sk_sndbuf >> 1);
}

static inline gfp_t gfp_any(void)
{
	return in_softirq() ? GFP_ATOMIC : GFP_KERNEL;
}

static inline long sock_rcvtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_rcvtimeo;
}

static inline long sock_sndtimeo(const struct sock *sk, int noblock)
{
	return noblock ? 0 : sk->sk_sndtimeo;
}

/*
 * 根据是否设置MSG_WAITALL标志来确定本次调用需要接收数据的长度.如果设置了MSG_WAITALL标志,则读取数据长度为用户调用时的输入参数len.
 */
static inline int sock_rcvlowat(const struct sock *sk, int waitall, int len)
{
	return (waitall ? len : min_t(int, sk->sk_rcvlowat, len)) ? : 1;
}

/* Alas, with timeout socket operations are not restartable.
 * Compare this to poll().
 */
static inline int sock_intr_errno(long timeo)
{
	return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
}

extern void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb);

static __inline__ void
sock_recv_timestamp(struct msghdr *msg, struct sock *sk, struct sk_buff *skb)
{
	ktime_t kt = skb->tstamp;
	struct skb_shared_hwtstamps *hwtstamps = skb_hwtstamps(skb);

	/*
	 * generate control messages if
	 * - receive time stamping in software requested (SOCK_RCVTSTAMP
	 *   or SOCK_TIMESTAMPING_RX_SOFTWARE)
	 * - software time stamp available and wanted
	 *   (SOCK_TIMESTAMPING_SOFTWARE)
	 * - hardware time stamps available and wanted
	 *   (SOCK_TIMESTAMPING_SYS_HARDWARE or
	 *   SOCK_TIMESTAMPING_RAW_HARDWARE)
	 */
	if (sock_flag(sk, SOCK_RCVTSTAMP) ||
	    sock_flag(sk, SOCK_TIMESTAMPING_RX_SOFTWARE) ||
	    (kt.tv64 && sock_flag(sk, SOCK_TIMESTAMPING_SOFTWARE)) ||
	    (hwtstamps->hwtstamp.tv64 &&
	     sock_flag(sk, SOCK_TIMESTAMPING_RAW_HARDWARE)) ||
	    (hwtstamps->syststamp.tv64 &&
	     sock_flag(sk, SOCK_TIMESTAMPING_SYS_HARDWARE)))
		__sock_recv_timestamp(msg, sk, skb);
	else
		sk->sk_stamp = kt;
}

extern void __sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
				     struct sk_buff *skb);

static inline void sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
					  struct sk_buff *skb)
{
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP)			| \
			   (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE)	| \
			   (1UL << SOCK_TIMESTAMPING_SOFTWARE)		| \
			   (1UL << SOCK_TIMESTAMPING_RAW_HARDWARE) 	| \
			   (1UL << SOCK_TIMESTAMPING_SYS_HARDWARE))

	if (sk->sk_flags & FLAGS_TS_OR_DROPS)
		__sock_recv_ts_and_drops(msg, sk, skb);
	else
		sk->sk_stamp = skb->tstamp;
}

/**
 * sock_tx_timestamp - checks whether the outgoing packet is to be time stamped
 * @msg:	outgoing packet
 * @sk:		socket sending this packet
 * @shtx:	filled with instructions for time stamping
 *
 * Currently only depends on SOCK_TIMESTAMPING* flags. Returns error code if
 * parameters are invalid.
 */
extern int sock_tx_timestamp(struct msghdr *msg,
			     struct sock *sk,
			     union skb_shared_tx *shtx);


/**
 * sk_eat_skb - Release a skb if it is no longer needed
 * @sk: socket to eat this skb from
 * @skb: socket buffer to eat
 * @copied_early: flag indicating whether DMA operations copied this data early
 *
 * This routine must be called with interrupts disabled or with the socket
 * locked so that the sk_buff queue operation is ok.
*/
#ifdef CONFIG_NET_DMA
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	if (!copied_early)
		__kfree_skb(skb);
	else
		__skb_queue_tail(&sk->sk_async_wait_queue, skb);
}
#else
static inline void sk_eat_skb(struct sock *sk, struct sk_buff *skb, int copied_early)
{
	__skb_unlink(skb, &sk->sk_receive_queue);
	__kfree_skb(skb);
}
#endif

static inline
struct net *sock_net(const struct sock *sk)
{
#ifdef CONFIG_NET_NS
	return sk->sk_net;
#else
	return &init_net;
#endif
}

static inline
void sock_net_set(struct sock *sk, struct net *net)
{
#ifdef CONFIG_NET_NS
	sk->sk_net = net;
#endif
}

/*
 * Kernel sockets, f.e. rtnl or icmp_socket, are a part of a namespace.
 * They should not hold a referrence to a namespace in order to allow
 * to stop it.
 * Sockets after sk_change_net should be released using sk_release_kernel
 */
static inline void sk_change_net(struct sock *sk, struct net *net)
{
	put_net(sock_net(sk));
	sock_net_set(sk, hold_net(net));
}

static inline struct sock *skb_steal_sock(struct sk_buff *skb)
{
	if (unlikely(skb->sk)) {
		struct sock *sk = skb->sk;

		skb->destructor = NULL;
		skb->sk = NULL;
		return sk;
	}
	return NULL;
}

extern void sock_enable_timestamp(struct sock *sk, int flag);
extern int sock_get_timestamp(struct sock *, struct timeval __user *);
extern int sock_get_timestampns(struct sock *, struct timespec __user *);

/* 
 *	Enable debug/info messages 
 */
extern int net_msg_warn;
#define NETDEBUG(fmt, args...) \
	do { if (net_msg_warn) printk(fmt,##args); } while (0)

#define LIMIT_NETDEBUG(fmt, args...) \
	do { if (net_msg_warn && net_ratelimit()) printk(fmt,##args); } while(0)

//下面这两个值的初始化在sk_init函数中，其值会收内存的影响，默认值可能不一样
extern __u32 sysctl_wmem_max;
extern __u32 sysctl_rmem_max;

extern void sk_init(void);

/* 用于控制传输控制块分配的选项缓存，该值为辅助缓冲区的上限值*/
extern int sysctl_optmem_max;

extern __u32 sysctl_wmem_default;//发送缓冲区默认值 SK_WMEM_MAX
extern __u32 sysctl_rmem_default;// 接收缓冲区大小的上限为SK_RMEM_MAX，默认值是sysctl_rmem_default，即32767也就是IP首部16位长度(最大65535)的一半

#endif	/* _SOCK_H */

/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/kmemcheck.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/netdevice.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>
#include <net/netns/hash.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options1 {
	__be32		faddr;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
};

/*
 * IP选项信息块，在IP选项处理中，IP选项信息块ip_options是
 * 最常用的结构，用来描述相关的IP选项。该结构可以用在SKB中，
 * 描述所在SKB的数据报中存在的选项，参见IP层中信息控制块
 * inet_skb_parm结构；也可以单独使用，如通过IP_OPTIONS选项
 * 和获取所在套接字发送数据报IP首部中的IP选项
 */ //setsockopt(sockfd, SOL_IP,IP_OPTIONS,(void*)opt,optlen);应用程序可以通过这个设置
//ip_options参考ip_options.c
struct ip_options { //数据接收的时候从SKB中获取IP选项字段，见ip_rcv_options
	/*
	 * 存在宽松源路由或严格源路由选项时，用来
	 * 记录下一跳的IP地址
	 */
	__be32		faddr;
	/*
	 * 标识IP首部中选项所占的字节数，包括__data之后的数据，
	 * 如果有的话
	 */
	unsigned char	optlen;
	/*
	 * 记录宽松源路由或严格源路由选项在IP首部中的偏移量，
	 * 即选项的第一个字节的地址减去IP首部的第一个字节的地址
	 */
	unsigned char	srr;
	/*
	 * 用于记录路径选项在IP首部中的偏移量
	 */
	unsigned char	rr;
	/*
	 * 用于记录时间戳选项在IP首部中的偏移量
	 */
	unsigned char	ts;
	/*
	 * 标识该IP选项是否有数据，若有则存放在__data字段起始的
	 * 存储空间内，即紧跟在ip_option结构后面。这里的数据不只
	 * 是选项数据，而是整个选项内容
	 */
	/*
	 * 标识该选项是IPOPT_SSRR，而不是IPOPT_LSRR
	 */
	unsigned char	is_strictroute:1,
			/*
			 * 表示目的地址是从源路由选项选出的
			 */
			srr_is_hit:1,
			/*
			 * 标识是否修改过IP首部，如果是则需要重新
			 * 计算IP首部校验和
			 */
			is_changed:1,
			/*
			 * 标识有IPOPT_RR选项，需要记录IP地址。
			 */
			rr_needaddr:1,
			/*
			 * ts_needtime标识有IPOPT_TIMESTAMP选项，需要
			 * 记录时间戳
			 * ts_needaddr标识有IPOPT_TIMESTAMP选项，需要
			 * 记录IP地址
			 */
			ts_needtime:1,
			ts_needaddr:1;
	/*
	 * 标识IPOPT_RA选项。路由器警告选项，表示路由器
	 * 应该更仔细地检查这个数据包
	 */
	unsigned char	router_alert;
	/*
	 * 用于记录商业IP安全选项在IP首部中的偏移量
	 */
	unsigned char	cipso;
	/*
	 * 未使用
	 */
	unsigned char	__pad2;
	/*
	 * 若选项有数据则从该字段开始，使之紧跟在ip_option结构后面，
	 * 最多不超过40B
	 */
	unsigned char	__data[0];
};


#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)
/*
 * 该结构主要描述双方的地址、所支持的TCP选项等
  tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
 *///request_sock_queue中的listen_sock里面的hash表syn_table中存储的这个结构
struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
#endif
	/*
	 * 本地端口号
	 */
	__be16			loc_port;
	/*
	 * 本地IP地址
	 */
	__be32			loc_addr;
	/*
	 * 对端IP地址
	 */
	__be32			rmt_addr;
	/*
	 * 对端端口号
	 */
	__be16			rmt_port;
	kmemcheck_bitfield_begin(flags);
	/*
	 * 发送窗口扩大因子，即要把TCP首部中指定的滑动窗口大小
	 * 左移snd_wscale位后，作为真正的滑动窗口大小。在TCP
	 * 首部中，滑动窗口大小值为16位的，而snd_wscale的值最大
	 * 只能为14。所以，滑动窗口最大可被扩展到30位，在协议栈
	 * 的实际实现中，可以看到窗口大小被置为5840，扩大因子为2，
	 * 即实际的窗口大小为5840<<2=23360B
	 */
	u16			snd_wscale : 4,
				/*
				 * 接收窗口扩大因子
				 */
				rcv_wscale : 4,
				/*
				 * 标识TCP段是否存在TCP时间戳选项
				 */
				tstamp_ok  : 1,
				/*
				 * 标识是否支持SACK，支持则该选项能出现在SYN段中
				 */
				sack_ok	   : 1,
				/*
				 * 标识是否支持窗口扩大因子，如果支持该选项也只能出现
				 * 在SYN段中
				 */
				wscale_ok  : 1,
				/*
				 * 标志是否启用了显式拥塞通知
				 */
				ecn_ok	   : 1,
				/*
				 * 标识已接收到第三次握手的ACK段，但是由于服务器繁忙
				 * 或其他原因导致未能建立起连接，此时可根据该标志重新
				 * 给客户端发送SYN+ACK段，再次进行连接的建立。该标志
				 * 的设置同时受sysctl_tcp_abort_on_overflow的控制
				 */
				acked	   : 1,
				no_srccheck: 1;
	kmemcheck_bitfield_end(flags);
	struct ip_options	*opt;//服务器端在接收到SYN后，会解析SKB中的ip选项字段，见tcp_v4_save_options
};

//tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
struct inet_request_sock1 {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
#endif
	__be16			loc_port;
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	kmemcheck_bitfield_begin(flags);
	u16			snd_wscale : 4,
				rcv_wscale : 4,
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1,
				no_srccheck: 1;
	kmemcheck_bitfield_end(flags);
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @inet_daddr - Foreign IPv4 addr
 * @inet_rcv_saddr - Bound local IPv4 addr
 * @inet_dport - Destination port
 * @inet_num - Local port
 * @inet_saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @inet_sport - Source port
 * @inet_id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
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

//套接字中本端和对端的相关信息都放在这里面，从而与对应的tcp_proc udp_proc等协议无关，保证与具体协议无关，所有协议都用这个公用结构
struct inet_sock {
    /* sk and pinet6 has to be the first two members of inet_sock */
    /*
     * sock结构是通用的网络层描述块，构成传输控制块的基础
     */
    struct sock     sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
    /* 如果支持IPv6特性，pinet6是指向IPv6控制块的指针 */
    struct ipv6_pinfo   *pinet6;
#endif
    /* Socket demultiplex comparisons on incoming packets. */
    /* 目的IP地址*/
    __be32          daddr;
    /*
     * 已绑定的本地IP地址。接收数据时，作为条件的一部分查找
     * 数据所属的传输控制块
     */
    __be32          rcv_saddr;
    /* 目的端口号*/
    __be16          dport;
    /* 主机字节序存储的本地端口。*/
    __u16           num;
    /*
     * 也标识本地IP地址，但在发送时使用。rcv_saddr和saddr
     * 都描述本地IP地址，但用途不同
     */
    __be32          saddr;
    /*
     * 单播报文的TTL,默认值为-1，表示使用默认的TTL值。
     * 在输出IP数据包时，TTL值首先从这里获取，若没有
     * 设置，则从路由缓存的metric中获取。参见IP_TTL
     * 套接字选项 
     */
    __s16           uc_ttl;
    /* 
     * 存放一些IPPROTO_IP级别的选项值，可能的取值为IP_CMSG_PKTINFO等
     */
    __u16           cmsg_flags;
    /* 指向IP数据包选项的指针*/
    struct ip_options   *opt;
    /* 由num转换成的网络字节序的源端口，也就是本地端口 */
    __be16          sport;
    /* 一个单调递增的值，用来赋给IP首部中的id域 */
    __u16           id;
    /* 用于设置IP数据包首部的TOS域，参见IP_TOS套接字选项 */
    __u8            tos;
    /* 用于设置多播数据包的TTL */
    __u8            mc_ttl;
    /* 
     * 标识套接字是否启用路径MTU发现功能，初始值根据系统
     * 控制参数ip_no_pmtu_disc来确定，参见IP_MTU_DISCOVER
     * 套接字选项。可能的取值有IP_PMTUDISC_DO等
     */
    __u8            pmtudisc;
    /*
     * 标识是否允许接收扩展的可靠错误信息。
     * 参见IP_RECVERR套接字选项
     */
    __u8            recverr:1,
    /*
     * 标识是否为基于连接的传输控制块，即是否为基于
     * inet_connection_sock结构的传输控制块，如TCP的传输控制块
     */
                is_icsk:1,
    /*
     * 标识是否允许绑定非主机地址，参见IP_FREEBIND套接字选项 
     *
     */
                freebind:1,
    /*
     * 标识IP首部是否由用户数据构建。该标识只用于RAW套接字，
     * 一旦设置后，IP选项中的IP_TTL和IP_TOS都将被忽略
     */
                hdrincl:1,
    /* 标识组播是否发向回路 */
                mc_loop:1,
                transparent:1,
                mc_all:1;
    /*
     * 发送组播报文的网络设备索引号。如果为0，则表示
     * 可以从任何网络设备发送
     */
    int         mc_index;
    /* 发送组播报文的源地址 */
    __be32          mc_addr;
    /* 所在套接字加入的组播地址列表 */
    struct ip_mc_socklist   *mc_list;
    struct {
        /* 可能的值为IPCORK_OPT或IPCORK_ALLFRAG*/
        unsigned int        flags;
        /* UDP数据包或原始IP数据包分片大小 */
        unsigned int        fragsize;
        /* 指向此次发送数据包的IP选项 */
        struct ip_options   *opt;
        /* 发送数据包使用的输出路由缓存项 */
        struct dst_entry    *dst;
        /* 当前发送的数据包的数据长度 */
        int         length; /* Total length of all frames */
        /* 输出IP数据包的目的地址 */
        __be32          addr;
        /* 
         * 用flowi结构来缓存目的地址、目的端口、源地址和源端口，
         * 构造UDP报文时有关信息就取自这里 
         */
        struct flowi        fl;
    } cork; /* UDP或原始IP在每次发送时缓存的一些临时信息。如UDP
     数据包或原始IP数据包分片的大小*/
};

struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			inet_daddr;
	__be32			inet_rcv_saddr;
	__be16			inet_dport;
	__u16			inet_num;
	__be32			inet_saddr;
	__s16			uc_ttl;
	__u16			cmsg_flags;
	__be16			inet_sport;
	__u16			inet_id;

	struct ip_options	*opt;
	__u8			tos;
	__u8			min_ttl;
	__u8			mc_ttl;
	__u8			pmtudisc;
	__u8			recverr:1,
				is_icsk:1,
				freebind:1,
				hdrincl:1,
				mc_loop:1,
				transparent:1,
				mc_all:1;
	int			mc_index;
	__be32			mc_addr;
	struct ip_mc_socklist	*mc_list;
	struct {
		unsigned int		flags;
		unsigned int		fragsize;
		struct ip_options	*opt;
		struct dst_entry	*dst;
		int			length; /* Total length of all frames */
		__be32			addr;
		struct flowi		fl;
	} cork;
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

extern u32 inet_ehash_secret;
extern void build_ehash_secret(void);

static inline unsigned int inet_ehashfn(struct net *net,
					const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	return jhash_3words((__force __u32) laddr,
			    (__force __u32) faddr,
			    ((__u32) lport) << 16 | (__force __u32)fport,
			    inet_ehash_secret + net_hash_mix(net));
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->inet_rcv_saddr;
	const __u16 lport = inet->inet_num;
	const __be32 faddr = inet->inet_daddr;
	const __be16 fport = inet->inet_dport;
	struct net *net = sock_net(sk);

	return inet_ehashfn(net, laddr, lport, faddr, fport);
}

static inline struct request_sock *inet_reqsk_alloc(struct request_sock_ops *ops)
{
	struct request_sock *req = reqsk_alloc(ops);
	struct inet_request_sock *ireq = inet_rsk(req);

	if (req != NULL) {
		kmemcheck_annotate_bitfield(ireq, flags);
		ireq->opt = NULL;
	}

	return req;
}

static inline __u8 inet_sk_flowi_flags(const struct sock *sk)
{
	return inet_sk(sk)->transparent ? FLOWI_FLAG_ANYSRC : 0;
}

#endif	/* _INET_SOCK_H */

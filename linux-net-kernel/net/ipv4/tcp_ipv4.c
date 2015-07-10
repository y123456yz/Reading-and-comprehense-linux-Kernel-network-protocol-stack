/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 *		IPv4 specific functions
 *
 *
 *		code split from:
 *		linux/ipv4/tcp.c
 *		linux/ipv4/tcp_input.c
 *		linux/ipv4/tcp_output.c
 *
 *		See tcp.c for author information
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

/*
 * Changes:
 *		David S. Miller	:	New socket lookup architecture.
 *					This code is dedicated to John Dyson.
 *		David S. Miller :	Change semantics of established hash,
 *					half is devoted to TIME_WAIT sockets
 *					and the rest go in the other half.
 *		Andi Kleen :		Add support for syncookies and fixed
 *					some bugs: ip options weren't passed to
 *					the TCP layer, missed a check for an
 *					ACK bit.
 *		Andi Kleen :		Implemented fast path mtu discovery.
 *	     				Fixed many serious bugs in the
 *					request_sock handling and moved
 *					most of it into the af independent code.
 *					Added tail drop and some other bugfixes.
 *					Added new listen semantics.
 *		Mike McLagan	:	Routing by source
 *	Juan Jose Ciarlante:		ip_dynaddr bits
 *		Andi Kleen:		various fixes.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year
 *					coma.
 *	Andi Kleen		:	Fix new listen.
 *	Andi Kleen		:	Fix accept error reporting.
 *	YOSHIFUJI Hideaki @USAGI and:	Support IPV6_V6ONLY socket option, which
 *	Alexey Kuznetsov		allow both IPv4 and IPv6 sockets to bind
 *					a single port at the same time.
 */


#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/times.h>
#include <linux/slab.h>

#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/timewait_sock.h>
#include <net/xfrm.h>
#include <net/netdma.h>

#include <linux/inet.h>
#include <linux/ipv6.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

int sysctl_tcp_tw_reuse __read_mostly;
int sysctl_tcp_low_latency __read_mostly;


#ifdef CONFIG_TCP_MD5SIG
static struct tcp_md5sig_key *tcp_v4_md5_do_lookup(struct sock *sk,
						   __be32 addr);
static int tcp_v4_md5_hash_hdr(char *md5_hash, struct tcp_md5sig_key *key,
			       __be32 daddr, __be32 saddr, struct tcphdr *th);
#else
static inline
struct tcp_md5sig_key *tcp_v4_md5_do_lookup(struct sock *sk, __be32 addr)
{
	return NULL;
}
#endif

//存放在tcp_prot的h.hashinfo中  //该变量初始化赋值在tcp_init
struct inet_hashinfo tcp_hashinfo;//tcp_prot套接口和IPV6的tcpv6_prot在这个hash表中，tcp套接字的struct sock通过inet_hash加入到该hash中 

static inline __u32 tcp_v4_init_sequence(struct sk_buff *skb)
{
	return secure_tcp_sequence_number(ip_hdr(skb)->daddr,
					  ip_hdr(skb)->saddr,
					  tcp_hdr(skb)->dest,
					  tcp_hdr(skb)->source);
}

int tcp_twsk_unique(struct sock *sk, struct sock *sktw, void *twp)
{
	const struct tcp_timewait_sock *tcptw = tcp_twsk(sktw);
	struct tcp_sock *tp = tcp_sk(sk);

	/* With PAWS, it is safe from the viewpoint
	   of data integrity. Even without PAWS it is safe provided sequence
	   spaces do not overlap i.e. at data rates <= 80Mbit/sec.

	   Actually, the idea is close to VJ's one, only timestamp cache is
	   held not per host, but per port pair and TW bucket is used as state
	   holder.

	   If TW bucket has been already destroyed we fall back to VJ's scheme
	   and use initial timestamp retrieved from peer table.
	 */
	if (tcptw->tw_ts_recent_stamp &&
	    (twp == NULL || (sysctl_tcp_tw_reuse &&
			     get_seconds() - tcptw->tw_ts_recent_stamp > 1))) {
		tp->write_seq = tcptw->tw_snd_nxt + 65535 + 2;
		if (tp->write_seq == 0)
			tp->write_seq = 1;
		tp->rx_opt.ts_recent	   = tcptw->tw_ts_recent;
		tp->rx_opt.ts_recent_stamp = tcptw->tw_ts_recent_stamp;
		sock_hold(sktw);
		return 1;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(tcp_twsk_unique);

/* This will initiate an outgoing connection. */
/*
 * 在套接字层检测完必要条件，如套接字的状态等之后，传输
 * 接口层中还需对传输控制块进行更详细的校验，如地址族的
 * 类型，是否获取到有效的路由入口。通过检测后设置传输控
 * 制块各字段值，如初始化时间戳，保存目的地址和目的端口
 * 等，最后构造并发送SYN段。
 */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct rtable *rt;
	__be32 daddr, nexthop;
	int tmp;
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	nexthop = daddr = usin->sin_addr.s_addr;//connect的时候s_addr里面对应的是目的地址，即对端ip地址
	if (inet->opt && inet->opt->srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet->opt->faddr;
	}

    /*
	 * 调用ip_route_connect()根据下一跳地址等信息查找目的路由缓存项，如果路由查找命中，则生成一个相应的路由缓存项，这个缓存项不但
	 * 可以用于当前待发送SYN段，而且对后续的所有数据包都可以起到一个加速路由查找的作用。
	 */
	tmp = ip_route_connect(&rt, nexthop, inet->inet_saddr,
			       RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
			       IPPROTO_TCP,
			       inet->inet_sport, usin->sin_port, sk, 1);
	if (tmp < 0) {
		if (tmp == -ENETUNREACH)
			IP_INC_STATS_BH(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
		return tmp;
	}

    /*TCP不能使用类型为组播或多播的路由缓存项。*/
	if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
		ip_rt_put(rt);
		return -ENETUNREACH;
	}

    /* 如果没有启用源路由选项，则使用获取到路由缓存项中的目的地址。*/
	if (!inet->opt || !inet->opt->srr)
		daddr = rt->rt_dst;

    /* 如果还未设置传输控制块中的源地址，则使用路由缓存项中的源地址对其进行设置。*/
    //这里说明了客户端在连接的时候可以不用指明本地IP地址，由路由缓存找到对应目的IP的时候，就可以确定本地IP地址了。
	if (!inet->inet_saddr)
		inet->inet_saddr = rt->rt_src;
	inet->inet_rcv_saddr = inet->inet_saddr;

    /* 如果传输控制块中的时间戳和目的地址已被使用过，则说明该传输控制块之前已建立连接并进行过通信，需重新初始化相关成员。 */
	if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
		/* Reset inherited state */
		tp->rx_opt.ts_recent	   = 0;
		tp->rx_opt.ts_recent_stamp = 0;
		tp->write_seq		   = 0;
	}

    /* 如果启用了sysctl_tw_recycle并接收过时间戳选项，从对端信息块中获取相应的值来初始化ts_recent_stamp和ts_recent。*/
	if (tcp_death_row.sysctl_tw_recycle &&
	    !tp->rx_opt.ts_recent_stamp && rt->rt_dst == daddr) {
		struct inet_peer *peer = rt_get_peer(rt);
		/*
		 * VJ's idea. We save last timestamp seen from
		 * the destination in peer table, when entering state
		 * TIME-WAIT * and initialize rx_opt.ts_recent from it,
		 * when trying new connection.
		 */
		if (peer != NULL &&
		    (u32)get_seconds() - peer->tcp_ts_stamp <= TCP_PAWS_MSL) {
			tp->rx_opt.ts_recent_stamp = peer->tcp_ts_stamp;
			tp->rx_opt.ts_recent = peer->tcp_ts;
		}
	}

	inet->inet_dport = usin->sin_port;
	inet->inet_daddr = daddr;

	inet_csk(sk)->icsk_ext_hdr_len = 0;
	if (inet->opt)
		inet_csk(sk)->icsk_ext_hdr_len = inet->opt->optlen;

	tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;

	/* Socket identity is still unknown (sport may be zero).
	 * However we set state to SYN-SENT and not releasing socket
	 * lock select source port, enter ourselves into the hash tables and
	 * complete initialization after this.
	 */
	 /* 将TCP设置为SYN_SENT，动态绑定一个本地端口，并将传输控制块添加到ehash散列表中。由于在动态分配端口时，如果找到的是已使用的端口，则
	 * 需在TIME_WAIT状态中进行相应的确认，因此调用inet_hash_connect()时需用timewait传输控制块和参数管理器tcp_death_row作为参数。*/
	tcp_set_state(sk, TCP_SYN_SENT);
	err = inet_hash_connect(&tcp_death_row, sk);
	if (err)
		goto failure;

	err = ip_route_newports(&rt, IPPROTO_TCP,
				inet->inet_sport, inet->inet_dport, sk);
	if (err)
		goto failure;

	/* OK, now commit destination to socket.  */
	/*
	 * 设置GSO类型为SKB_GSO_TCPV4，并根据该传输
	 * 控制块的路由输出设置特性设置传输控制
	 * 块中目的路由网络设备的特性。
	 */
	sk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(sk, &rt->u.dst);

    /*
	 * 如果write_seq字段值为零，则说明该传输控制块还
	 * 未设置初始序号，因此需调用secure_tcp_sequence_number()，
	 * 根据双方的地址、端口计算初始序列号，同时根据
	 * 发送需要和当前时间得到用于设置IP首部ID域的值。
	 */
	if (!tp->write_seq)
		tp->write_seq = secure_tcp_sequence_number(inet->inet_saddr,
							   inet->inet_daddr,
							   inet->inet_sport,
							   usin->sin_port);

	inet->inet_id = tp->write_seq ^ jiffies;

    /*
	 * 最后调用tcp_connect()来构造并发送SYN段。
	 */
	err = tcp_connect(sk);
	rt = NULL;
	if (err)
		goto failure;

	return 0;

failure:
	/*
	 * This unhashes the socket and releases the local port,
	 * if necessary.
	 */
	tcp_set_state(sk, TCP_CLOSE);
	ip_rt_put(rt);
	sk->sk_route_caps = 0;
	inet->inet_dport = 0;
	return err;
}

/*
 * This routine does path mtu discovery as defined in RFC1191.
 */
/*
 * ICMP模块接收到"需要分片ICMP目的不可达报文"的消息后，
 * 根据传输层协议，如果是TCP，则会调用tcp_v4_err()，在该
 * 函数中进而根据类型ICMP_DEST_UNREACH和编码ICMP_FRAG_NEEDED
 * 调用do_pmtu_discovery()进行路径MTU发现失败处理。
 */
static void do_pmtu_discovery(struct sock *sk, struct iphdr *iph, u32 mtu)
{
    struct dst_entry *dst;
    struct inet_sock *inet = inet_sk(sk);

    /* We are not interested in TCP_LISTEN and open_requests (SYN-ACKs
     * send out by Linux are always <576bytes so they should go through
     * unfragmented).
     */
    /*
     * 在监听状态下，不需要进行路径MTU发现，因为在该
     * 状态下输出的SYN+ACK段总是小于536B，因此输出的IP
     * 数据包不会被分片。
     */
    if (sk->sk_state == TCP_LISTEN)
        return;

    /* We don't check in the destentry if pmtu discovery is forbidden
     * on this route. We just assume that no packet_to_big packets
     * are send back when pmtu discovery is not active.
     * There is a small race when the user changes this flag in the
     * route, but I think that's acceptable.
     */
    /*
     * 检测当前传输控制块的路由缓存项是否可用。如果
     * 失效，则不继续处理。
     */
    if ((dst = __sk_dst_check(sk, 0)) == NULL)
        return;

    /*
     * 在没有锁定路由缓存项的度量值的情况下，将获取的
     * 下一跳MTU更新到与路由相关的路由缓存项的度量值中。
     * 如果存储在路由缓存项的度量值中的PTMU大于下一跳的
     * MTU，且发送出的IP数据包禁止分片，则需报告相应的
     * 错误。
     */
    dst->ops->update_pmtu(dst, mtu);

    /* Something is about to be wrong... Remember soft error
     * for the case, if this connection will not able to recover.
     */
    if (mtu < dst_mtu(dst) && ip_dont_fragment(sk, dst))
        sk->sk_err_soft = EMSGSIZE;

    mtu = dst_mtu(dst);

    /*
     * 在允许路径MTU发现的情况下，如果缓存在传输控制块
     * 中的路径MTU值大于新的值，则需将新的路径MTU值更新
     * 到传输控制块的缓存中，同时更新MSS，最后重传。
     */
    if (inet->pmtudisc != IP_PMTUDISC_DONT &&
        inet_csk(sk)->icsk_pmtu_cookie > mtu) {
        tcp_sync_mss(sk, mtu);

        /* Resend the TCP packet because it's
         * clear that the old packet has been
         * dropped. This is the new "fast" path mtu
         * discovery.
         */
        tcp_simple_retransmit(sk);
    } /* else let the usual retransmit timer handle it */
}

static void do_pmtu_discovery1(struct sock *sk, struct iphdr *iph, u32 mtu)
{
	struct dst_entry *dst;
	struct inet_sock *inet = inet_sk(sk);

	/* We are not interested in TCP_LISTEN and open_requests (SYN-ACKs
	 * send out by Linux are always <576bytes so they should go through
	 * unfragmented).
	 */
	if (sk->sk_state == TCP_LISTEN)
		return;

	/* We don't check in the destentry if pmtu discovery is forbidden
	 * on this route. We just assume that no packet_to_big packets
	 * are send back when pmtu discovery is not active.
	 * There is a small race when the user changes this flag in the
	 * route, but I think that's acceptable.
	 */
	if ((dst = __sk_dst_check(sk, 0)) == NULL)
		return;

	dst->ops->update_pmtu(dst, mtu);

	/* Something is about to be wrong... Remember soft error
	 * for the case, if this connection will not able to recover.
	 */
	if (mtu < dst_mtu(dst) && ip_dont_fragment(sk, dst))
		sk->sk_err_soft = EMSGSIZE;

	mtu = dst_mtu(dst);

	if (inet->pmtudisc != IP_PMTUDISC_DONT &&
	    inet_csk(sk)->icsk_pmtu_cookie > mtu) {
		tcp_sync_mss(sk, mtu);

		/* Resend the TCP packet because it's
		 * clear that the old packet has been
		 * dropped. This is the new "fast" path mtu
		 * discovery.
		 */
		tcp_simple_retransmit(sk);
	} /* else let the usual retransmit timer handle it */
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition.  If err < 0 then the socket should
 * be closed and the error returned to the user.  If err > 0
 * it's just the icmp type << 8 | icmp code.  After adjustment
 * header points to the first 8 bytes of the tcp header.  We need
 * to find the appropriate port.
 *
 * The locking strategy used here is very "optimistic". When
 * someone else accesses the socket the ICMP is just dropped
 * and for some paths there is no check at all.
 * A more general error queue to queue errors for later handling
 * is probably better.
 *
 */
    /*
     * 目的不可达、源端被关闭、超时、参数错误这四种类型
     * 的差错ICMP报文，都是由同一个函数icmp_unreach()来处理的，
     * 对其中目的不可达、源端被关闭这两种类型ICMP报文
     * 因要提取某些信息而需作一些特殊的处理，而另外
     * 一些则不需要，根据差错报文中的信息直接调用
     * 传输层的错误处理例程。参见<Linux内核源码剖析348页>
     CMP差错报文的数据部分包括:原始数据报的IP首部再加上前8个字节的数据部分(2字节源端口+2字节目的端口+4字节序号)
     */
void tcp_v4_err(struct sk_buff *icmp_skb, u32 info)
{
	struct iphdr *iph = (struct iphdr *)icmp_skb->data;
	struct tcphdr *th = (struct tcphdr *)(icmp_skb->data + (iph->ihl << 2));
	struct inet_connection_sock *icsk;
	struct tcp_sock *tp;
	struct inet_sock *inet;
	const int type = icmp_hdr(icmp_skb)->type;
	const int code = icmp_hdr(icmp_skb)->code;
	struct sock *sk;
	struct sk_buff *skb;
	__u32 seq;
	__u32 remaining;
	int err;
	struct net *net = dev_net(icmp_skb->dev);

    /*
	 * 检测ICMP报文长度是否包含了原始IP首部和原始IP数据包中
	 * 前8字节数据，如果不完整则返回
	 */
	if (icmp_skb->len < (iph->ihl << 2) + 8) {
		ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
		return;
	}

    /*
	 * 通过从ICMP报文数据中获取的原始TCP首部中源端口号和IP首部
	 * 中源地址，得到发送该TCP报文的传输控制块。如果获取失败，
	 * 则说明ICMP报文有误或该套接字已关闭；如果获取传输控制块
	 * 的TCP状态为TIME_WAIT，则说明套接字即将关闭，这两种情况
	 * 都无需进一步处理
	 */
	sk = inet_lookup(net, &tcp_hashinfo, iph->daddr, th->dest,
			iph->saddr, th->source, inet_iif(icmp_skb));
	if (!sk) {
		ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
		return;
	}
	if (sk->sk_state == TCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
		return;
	}

	bh_lock_sock(sk);
	/* If too many ICMPs get dropped on busy
	 * servers this needs to be solved differently.
	 *//*
	 * 如果此时该传输控制块被用户进程锁定(如用户进程正在调用
	 * send等系统调用)，则需累计相关SNMP的统计量
	 */
	if (sock_owned_by_user(sk))
		NET_INC_STATS_BH(net, LINUX_MIB_LOCKDROPPEDICMPS);

	if (sk->sk_state == TCP_CLOSE)
		goto out;

	if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
		NET_INC_STATS_BH(net, LINUX_MIB_TCPMINTTLDROP);
		goto out;
	}

    /*
         * 如果传输控制块不再侦听状态，且序号不再已发送未确认的区间内，则
         * ICMP报文异常，无需进一步处理
         */

	icsk = inet_csk(sk);
	tp = tcp_sk(sk);
	seq = ntohl(th->seq);
	if (sk->sk_state != TCP_LISTEN &&
	    !between(seq, tp->snd_una, tp->snd_nxt)) {
		NET_INC_STATS_BH(net, LINUX_MIB_OUTOFWINDOWICMPS);
		goto out;
	}

	switch (type) {
	case ICMP_SOURCE_QUENCH:
		/* Just silently ignore these. */
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		break;
		/*
	 * 处理目的不可达类型，首先检测代码的合法性，然后根据
	 * 代码具体处理:如果需要分片而设置了不可分片，则调用
	 * do_pmtu_discovery()探测路径MTU；其他编码，则获取
	 * 对应的错误码
	 */
	case ICMP_DEST_UNREACH:
		if (code > NR_ICMP_UNREACH)
			goto out;

		if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */
			if (!sock_owned_by_user(sk))
				do_pmtu_discovery(sk, iph, info);
			goto out;
		}

		err = icmp_err_convert[code].errno;
		/* check if icmp_skb allows revert of backoff
		 * (see draft-zimmermann-tcp-lcd) */
		if (code != ICMP_NET_UNREACH && code != ICMP_HOST_UNREACH)
			break;
		if (seq != tp->snd_una  || !icsk->icsk_retransmits ||
		    !icsk->icsk_backoff)
			break;

		if (sock_owned_by_user(sk))
			break;

		icsk->icsk_backoff--;
		inet_csk(sk)->icsk_rto = __tcp_set_rto(tp) <<
					 icsk->icsk_backoff;
		tcp_bound_rto(sk);

		skb = tcp_write_queue_head(sk);
		BUG_ON(!skb);

		remaining = icsk->icsk_rto - min(icsk->icsk_rto,
				tcp_time_stamp - TCP_SKB_CB(skb)->when);

		if (remaining) {
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
						  remaining, TCP_RTO_MAX);
		} else {
			/* RTO revert clocked out retransmission.
			 * Will retransmit now */
			tcp_retransmit_timer(sk);
		}

		break;
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	default:
		goto out;
	}

	switch (sk->sk_state) {
		struct request_sock *req, **prev;
	case TCP_LISTEN:
	    /*
		 * 如果传输控制块被用户进程锁定，则不作进一步处理
		 */
		if (sock_owned_by_user(sk))
			goto out;

        /*
		 * 由于处于监听状态，因此根据目的端口号、源地址和目的地址查找
		 * 正在连接的对端套接字，如果查找失败则不作进一步处理
		 */
		req = inet_csk_search_req(sk, &prev, th->dest,
					  iph->daddr, iph->saddr);
		if (!req)
			goto out;

		/* ICMPs are not backlogged, hence we cannot get
		   an established socket here.
		 */
		WARN_ON(req->sk);

        /*
		 * 如果发送出去TCP段的序号不等于对端套接字中的发送序号，
		 * 则说明序号有误，不作进一步处理
		 */
		if (seq != tcp_rsk(req)->snt_isn) {
			NET_INC_STATS_BH(net, LINUX_MIB_OUTOFWINDOWICMPS);
			goto out;
		}

		/*
		 * Still in SYN_RECV, just remove it silently.
		 * There is no good way to pass the error to the newly
		 * created socket, and POSIX does not want network
		 * errors returned from accept().
		 */
		 /*
		 * 删除并释放连接过程中的传输控制块
		 */
		inet_csk_reqsk_queue_drop(sk, req, prev);
		goto out;

	case TCP_SYN_SENT:
	case TCP_SYN_RECV:  /* Cannot happen.
			       It can f.e. if SYNs crossed.
			     *//*
		 * 如果传输控制块没有被用户进程锁定，则将错误码设置到sk_err，
		 * 调用该套接字的错误报告借口函数，关闭套接字；否则将错误码
		 * 设置到sk_err_soft，在这种情况下用户进程可使用SO_ERROR套接
		 * 字选项获取错误码
		 */
		if (!sock_owned_by_user(sk)) {
			sk->sk_err = err;

			sk->sk_error_report(sk);

			tcp_done(sk);
		} else {
			sk->sk_err_soft = err;
		}
		goto out;
	}

	/* If we've already connected we will keep trying
	 * until we time out, or the user gives up.
	 *
	 * rfc1122 4.2.3.9 allows to consider as hard errors
	 * only PROTO_UNREACH and PORT_UNREACH (well, FRAG_FAILED too,
	 * but it is obsoleted by pmtu discovery).
	 *
	 * Note, that in modern internet, where routing is unreliable
	 * and in each dark corner broken firewalls sit, sending random
	 * errors ordered by their masters even this two messages finally lose
	 * their original sense (even Linux sends invalid PORT_UNREACHs)
	 *
	 * Now we are in compliance with RFCs.
	 *							--ANK (980905)
	 */

    /*
	 * 到这一步，则传输控制块一定不再LISTEN、SYN_SENT或SYN_RECV状态，
	 * 此时如果控制块没有被用户进程锁定，并且允许接收扩展的可靠错误
	 * 信息，则设置得到的错误码，然后通知错误；否则将错误码设置到sk_err_soft
	 */
	inet = inet_sk(sk);
	if (!sock_owned_by_user(sk) && inet->recverr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else	{ /* Only an error on timeout */
		sk->sk_err_soft = err;
	}

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * 基于TCP用户数据的中间累加和(如果存在数据)，生成TCP包的校验和
 */ //这是TCP输出的时候的校验和tcp_v4_send_check, TCP输入的时候计算校验和用的tcp_v4_checksum_init
static void __tcp_v4_send_check(struct sk_buff *skb,
				__be32 saddr, __be32 daddr)
{
	struct tcphdr *th = tcp_hdr(skb);

    /*
	 * 如果TCP包本身的校验由硬件来完成，则只执行伪首部校验和
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
	    /*
		 * 对于用软件完成校验和的操作，则基于TCP用户数据的中间累加和，
		 * 生成TCP包的校验和
		 */
		th->check = tcp_v4_check(skb->len, saddr, daddr,
					 csum_partial(th,
						      th->doff << 2,
						      skb->csum));
	}
}

/* This routine computes an IPv4 TCP checksum. */
/*
 * 基于TCP用户数据的中间累加和(如果存在数据)，生成TCP包的校验和
 *///这是TCP输出的时候的校验和tcp_v4_send_check, TCP输入的时候计算校验和用的tcp_v4_checksum_init
void tcp_v4_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);

	__tcp_v4_send_check(skb, inet->inet_saddr, inet->inet_daddr);
}

int tcp_v4_gso_send_check(struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct tcphdr *th;

	if (!pskb_may_pull(skb, sizeof(*th)))
		return -EINVAL;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	th->check = 0;
	skb->ip_summed = CHECKSUM_PARTIAL;
	__tcp_v4_send_check(skb, iph->saddr, iph->daddr);
	return 0;
}

/*
 *	This routine will send an RST to the other tcp.
 *
 *	Someone asks: why I NEVER use socket parameters (TOS, TTL etc.)
 *		      for reset.
 *	Answer: if a packet caused RST, it is not for a socket
 *		existing in our system, if it is matched to a socket,
 *		it is just duplicate segment or bug in other side's TCP.
 *		So that we build reply only basing on parameters
 *		arrived with segment.
 *	Exception: precedence violation. We do not implement it in any case.
 */

static void tcp_v4_send_reset(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct {
		struct tcphdr th;
#ifdef CONFIG_TCP_MD5SIG
		__be32 opt[(TCPOLEN_MD5SIG_ALIGNED >> 2)];
#endif
	} rep;
	struct ip_reply_arg arg;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif
	struct net *net;

	/* Never send a reset in response to a reset. */
	if (th->rst)
		return;

	if (skb_rtable(skb)->rt_type != RTN_LOCAL)
		return;

	/* Swap the send and the receive. */
	memset(&rep, 0, sizeof(rep));
	rep.th.dest   = th->source;
	rep.th.source = th->dest;
	rep.th.doff   = sizeof(struct tcphdr) / 4;
	rep.th.rst    = 1;

	if (th->ack) {
		rep.th.seq = th->ack_seq;
	} else {
		rep.th.ack = 1;
		rep.th.ack_seq = htonl(ntohl(th->seq) + th->syn + th->fin +
				       skb->len - (th->doff << 2));
	}

	memset(&arg, 0, sizeof(arg));
	arg.iov[0].iov_base = (unsigned char *)&rep;
	arg.iov[0].iov_len  = sizeof(rep.th);

#ifdef CONFIG_TCP_MD5SIG
	key = sk ? tcp_v4_md5_do_lookup(sk, ip_hdr(skb)->daddr) : NULL;
	if (key) {
		rep.opt[0] = htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_NOP << 16) |
				   (TCPOPT_MD5SIG << 8) |
				   TCPOLEN_MD5SIG);
		/* Update length and the length the header thinks exists */
		arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
		rep.th.doff = arg.iov[0].iov_len / 4;

		tcp_v4_md5_hash_hdr((__u8 *) &rep.opt[1],
				     key, ip_hdr(skb)->saddr,
				     ip_hdr(skb)->daddr, &rep.th);
	}
#endif
	arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
				      ip_hdr(skb)->saddr, /* XXX */
				      arg.iov[0].iov_len, IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;
	arg.flags = (sk && inet_sk(sk)->transparent) ? IP_REPLY_ARG_NOSRCCHECK : 0;

	net = dev_net(skb_dst(skb)->dev);
	ip_send_reply(net->ipv4.tcp_sock, skb,
		      &arg, arg.iov[0].iov_len);

	TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
	TCP_INC_STATS_BH(net, TCP_MIB_OUTRSTS);
}

/* The code following below sending ACKs in SYN-RECV and TIME-WAIT states
   outside socket context is ugly, certainly. What can I do?
 */

static void tcp_v4_send_ack(struct sk_buff *skb, u32 seq, u32 ack,
			    u32 win, u32 ts, int oif,
			    struct tcp_md5sig_key *key,
			    int reply_flags)
{
	struct tcphdr *th = tcp_hdr(skb);
	struct {
		struct tcphdr th;
		__be32 opt[(TCPOLEN_TSTAMP_ALIGNED >> 2)
#ifdef CONFIG_TCP_MD5SIG
			   + (TCPOLEN_MD5SIG_ALIGNED >> 2)
#endif
			];
	} rep;
	struct ip_reply_arg arg;
	struct net *net = dev_net(skb_dst(skb)->dev);

	memset(&rep.th, 0, sizeof(struct tcphdr));
	memset(&arg, 0, sizeof(arg));

	arg.iov[0].iov_base = (unsigned char *)&rep;
	arg.iov[0].iov_len  = sizeof(rep.th);
	if (ts) {
		rep.opt[0] = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
		rep.opt[1] = htonl(tcp_time_stamp);
		rep.opt[2] = htonl(ts);
		arg.iov[0].iov_len += TCPOLEN_TSTAMP_ALIGNED;
	}

	/* Swap the send and the receive. */
	rep.th.dest    = th->source;
	rep.th.source  = th->dest;
	rep.th.doff    = arg.iov[0].iov_len / 4;
	rep.th.seq     = htonl(seq);
	rep.th.ack_seq = htonl(ack);
	rep.th.ack     = 1;
	rep.th.window  = htons(win);

#ifdef CONFIG_TCP_MD5SIG
	if (key) {
		int offset = (ts) ? 3 : 0;

		rep.opt[offset++] = htonl((TCPOPT_NOP << 24) |
					  (TCPOPT_NOP << 16) |
					  (TCPOPT_MD5SIG << 8) |
					  TCPOLEN_MD5SIG);
		arg.iov[0].iov_len += TCPOLEN_MD5SIG_ALIGNED;
		rep.th.doff = arg.iov[0].iov_len/4;

		tcp_v4_md5_hash_hdr((__u8 *) &rep.opt[offset],
				    key, ip_hdr(skb)->saddr,
				    ip_hdr(skb)->daddr, &rep.th);
	}
#endif
	arg.flags = reply_flags;
	arg.csum = csum_tcpudp_nofold(ip_hdr(skb)->daddr,
				      ip_hdr(skb)->saddr, /* XXX */
				      arg.iov[0].iov_len, IPPROTO_TCP, 0);
	arg.csumoffset = offsetof(struct tcphdr, check) / 2;
	if (oif)
		arg.bound_dev_if = oif;

	ip_send_reply(net->ipv4.tcp_sock, skb,
		      &arg, arg.iov[0].iov_len);

	TCP_INC_STATS_BH(net, TCP_MIB_OUTSEGS);
}

static void tcp_v4_timewait_ack(struct sock *sk, struct sk_buff *skb)
{
	struct inet_timewait_sock *tw = inet_twsk(sk);
	struct tcp_timewait_sock *tcptw = tcp_twsk(sk);

	tcp_v4_send_ack(skb, tcptw->tw_snd_nxt, tcptw->tw_rcv_nxt,
			tcptw->tw_rcv_wnd >> tw->tw_rcv_wscale,
			tcptw->tw_ts_recent,
			tw->tw_bound_dev_if,
			tcp_twsk_md5_key(tcptw),
			tw->tw_transparent ? IP_REPLY_ARG_NOSRCCHECK : 0
			);

	inet_twsk_put(tw);
}

static void tcp_v4_reqsk_send_ack(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req)
{
	tcp_v4_send_ack(skb, tcp_rsk(req)->snt_isn + 1,
			tcp_rsk(req)->rcv_isn + 1, req->rcv_wnd,
			req->ts_recent,
			0,
			tcp_v4_md5_do_lookup(sk, ip_hdr(skb)->daddr),
			inet_rsk(req)->no_srccheck ? IP_REPLY_ARG_NOSRCCHECK : 0);
}

/*
 *	Send a SYN-ACK after having received a SYN.
 *	This still operates on a request_sock only, not on a big
 *	socket.
 */
static int tcp_v4_send_synack(struct sock *sk, struct dst_entry *dst,
			      struct request_sock *req,
			      struct request_values *rvp)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int err = -1;
	struct sk_buff * skb;

	/* First, grab a route. */
	if (!dst && (dst = inet_csk_route_req(sk, req)) == NULL)
		return -1;

	skb = tcp_make_synack(sk, dst, req, rvp);

	if (skb) {
		__tcp_v4_send_check(skb, ireq->loc_addr, ireq->rmt_addr);

		err = ip_build_and_send_pkt(skb, sk, ireq->loc_addr,
					    ireq->rmt_addr,
					    ireq->opt);
		err = net_xmit_eval(err);
	}

	dst_release(dst);
	return err;
}

static int tcp_v4_rtx_synack(struct sock *sk, struct request_sock *req,
			      struct request_values *rvp)
{
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_RETRANSSEGS);
	return tcp_v4_send_synack(sk, NULL, req, rvp);
}

/*
 *	IPv4 request_sock destructor.
 */
static void tcp_v4_reqsk_destructor(struct request_sock *req)
{
	kfree(inet_rsk(req)->opt);
}

#ifdef CONFIG_SYN_COOKIES
static void syn_flood_warning(struct sk_buff *skb)
{
	static unsigned long warntime;

	if (time_after(jiffies, (warntime + HZ * 60))) {
		warntime = jiffies;
		printk(KERN_INFO
		       "possible SYN flooding on port %d. Sending cookies.\n",
		       ntohs(tcp_hdr(skb)->dest));
	}
}
#endif

/*
 * Save and compile IPv4 options into the request_sock if needed.
 */
static struct ip_options *tcp_v4_save_options(struct sock *sk,
					      struct sk_buff *skb)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	struct ip_options *dopt = NULL;

	if (opt && opt->optlen) {
		int opt_size = optlength(opt);
		dopt = kmalloc(opt_size, GFP_ATOMIC);
		if (dopt) {
			if (ip_options_echo(dopt, skb)) {
				kfree(dopt);
				dopt = NULL;
			}
		}
	}
	return dopt;
}

#ifdef CONFIG_TCP_MD5SIG
/*
 * RFC2385 MD5 checksumming requires a mapping of
 * IP address->MD5 Key.
 * We need to maintain these in the sk structure.
 */

/* Find the Key structure for an address.  */
static struct tcp_md5sig_key *
			tcp_v4_md5_do_lookup(struct sock *sk, __be32 addr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	if (!tp->md5sig_info || !tp->md5sig_info->entries4)
		return NULL;
	for (i = 0; i < tp->md5sig_info->entries4; i++) {
		if (tp->md5sig_info->keys4[i].addr == addr)
			return &tp->md5sig_info->keys4[i].base;
	}
	return NULL;
}

struct tcp_md5sig_key *tcp_v4_md5_lookup(struct sock *sk,
					 struct sock *addr_sk)
{
	return tcp_v4_md5_do_lookup(sk, inet_sk(addr_sk)->inet_daddr);
}

EXPORT_SYMBOL(tcp_v4_md5_lookup);

static struct tcp_md5sig_key *tcp_v4_reqsk_md5_lookup(struct sock *sk,
						      struct request_sock *req)
{
	return tcp_v4_md5_do_lookup(sk, inet_rsk(req)->rmt_addr);
}

/* This can be called on a newly created socket, from other files */
int tcp_v4_md5_do_add(struct sock *sk, __be32 addr,
		      u8 *newkey, u8 newkeylen)
{
	/* Add Key to the list */
	struct tcp_md5sig_key *key;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp4_md5sig_key *keys;

	key = tcp_v4_md5_do_lookup(sk, addr);
	if (key) {
		/* Pre-existing entry - just update that one. */
		kfree(key->key);
		key->key = newkey;
		key->keylen = newkeylen;
	} else {
		struct tcp_md5sig_info *md5sig;

		if (!tp->md5sig_info) {
			tp->md5sig_info = kzalloc(sizeof(*tp->md5sig_info),
						  GFP_ATOMIC);
			if (!tp->md5sig_info) {
				kfree(newkey);
				return -ENOMEM;
			}
			sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		}
		if (tcp_alloc_md5sig_pool(sk) == NULL) {
			kfree(newkey);
			return -ENOMEM;
		}
		md5sig = tp->md5sig_info;

		if (md5sig->alloced4 == md5sig->entries4) {
			keys = kmalloc((sizeof(*keys) *
					(md5sig->entries4 + 1)), GFP_ATOMIC);
			if (!keys) {
				kfree(newkey);
				tcp_free_md5sig_pool();
				return -ENOMEM;
			}

			if (md5sig->entries4)
				memcpy(keys, md5sig->keys4,
				       sizeof(*keys) * md5sig->entries4);

			/* Free old key list, and reference new one */
			kfree(md5sig->keys4);
			md5sig->keys4 = keys;
			md5sig->alloced4++;
		}
		md5sig->entries4++;
		md5sig->keys4[md5sig->entries4 - 1].addr        = addr;
		md5sig->keys4[md5sig->entries4 - 1].base.key    = newkey;
		md5sig->keys4[md5sig->entries4 - 1].base.keylen = newkeylen;
	}
	return 0;
}

EXPORT_SYMBOL(tcp_v4_md5_do_add);

static int tcp_v4_md5_add_func(struct sock *sk, struct sock *addr_sk,
			       u8 *newkey, u8 newkeylen)
{
	return tcp_v4_md5_do_add(sk, inet_sk(addr_sk)->inet_daddr,
				 newkey, newkeylen);
}

int tcp_v4_md5_do_del(struct sock *sk, __be32 addr)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int i;

	for (i = 0; i < tp->md5sig_info->entries4; i++) {
		if (tp->md5sig_info->keys4[i].addr == addr) {
			/* Free the key */
			kfree(tp->md5sig_info->keys4[i].base.key);
			tp->md5sig_info->entries4--;

			if (tp->md5sig_info->entries4 == 0) {
				kfree(tp->md5sig_info->keys4);
				tp->md5sig_info->keys4 = NULL;
				tp->md5sig_info->alloced4 = 0;
			} else if (tp->md5sig_info->entries4 != i) {
				/* Need to do some manipulation */
				memmove(&tp->md5sig_info->keys4[i],
					&tp->md5sig_info->keys4[i+1],
					(tp->md5sig_info->entries4 - i) *
					 sizeof(struct tcp4_md5sig_key));
			}
			tcp_free_md5sig_pool();
			return 0;
		}
	}
	return -ENOENT;
}

EXPORT_SYMBOL(tcp_v4_md5_do_del);

static void tcp_v4_clear_md5_list(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Free each key, then the set of key keys,
	 * the crypto element, and then decrement our
	 * hold on the last resort crypto.
	 */
	if (tp->md5sig_info->entries4) {
		int i;
		for (i = 0; i < tp->md5sig_info->entries4; i++)
			kfree(tp->md5sig_info->keys4[i].base.key);
		tp->md5sig_info->entries4 = 0;
		tcp_free_md5sig_pool();
	}
	if (tp->md5sig_info->keys4) {
		kfree(tp->md5sig_info->keys4);
		tp->md5sig_info->keys4 = NULL;
		tp->md5sig_info->alloced4  = 0;
	}
}

static int tcp_v4_parse_md5_keys(struct sock *sk, char __user *optval,
				 int optlen)
{
	struct tcp_md5sig cmd;
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpm_addr;
	u8 *newkey;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(&cmd, optval, sizeof(cmd)))
		return -EFAULT;

	if (sin->sin_family != AF_INET)
		return -EINVAL;

	if (!cmd.tcpm_key || !cmd.tcpm_keylen) {
		if (!tcp_sk(sk)->md5sig_info)
			return -ENOENT;
		return tcp_v4_md5_do_del(sk, sin->sin_addr.s_addr);
	}

	if (cmd.tcpm_keylen > TCP_MD5SIG_MAXKEYLEN)
		return -EINVAL;

	if (!tcp_sk(sk)->md5sig_info) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct tcp_md5sig_info *p;

		p = kzalloc(sizeof(*p), sk->sk_allocation);
		if (!p)
			return -EINVAL;

		tp->md5sig_info = p;
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
	}

	newkey = kmemdup(cmd.tcpm_key, cmd.tcpm_keylen, sk->sk_allocation);
	if (!newkey)
		return -ENOMEM;
	return tcp_v4_md5_do_add(sk, sin->sin_addr.s_addr,
				 newkey, cmd.tcpm_keylen);
}

static int tcp_v4_md5_hash_pseudoheader(struct tcp_md5sig_pool *hp,
					__be32 daddr, __be32 saddr, int nbytes)
{
	struct tcp4_pseudohdr *bp;
	struct scatterlist sg;

	bp = &hp->md5_blk.ip4;

	/*
	 * 1. the TCP pseudo-header (in the order: source IP address,
	 * destination IP address, zero-padded protocol number, and
	 * segment length)
	 */
	bp->saddr = saddr;
	bp->daddr = daddr;
	bp->pad = 0;
	bp->protocol = IPPROTO_TCP;
	bp->len = cpu_to_be16(nbytes);

	sg_init_one(&sg, bp, sizeof(*bp));
	return crypto_hash_update(&hp->md5_desc, &sg, sizeof(*bp));
}

static int tcp_v4_md5_hash_hdr(char *md5_hash, struct tcp_md5sig_key *key,
			       __be32 daddr, __be32 saddr, struct tcphdr *th)
{
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;
	if (tcp_v4_md5_hash_pseudoheader(hp, daddr, saddr, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

int tcp_v4_md5_hash_skb(char *md5_hash, struct tcp_md5sig_key *key,
			struct sock *sk, struct request_sock *req,
			struct sk_buff *skb)
{
	struct tcp_md5sig_pool *hp;
	struct hash_desc *desc;
	struct tcphdr *th = tcp_hdr(skb);
	__be32 saddr, daddr;

	if (sk) {
		saddr = inet_sk(sk)->inet_saddr;
		daddr = inet_sk(sk)->inet_daddr;
	} else if (req) {
		saddr = inet_rsk(req)->loc_addr;
		daddr = inet_rsk(req)->rmt_addr;
	} else {
		const struct iphdr *iph = ip_hdr(skb);
		saddr = iph->saddr;
		daddr = iph->daddr;
	}

	hp = tcp_get_md5sig_pool();
	if (!hp)
		goto clear_hash_noput;
	desc = &hp->md5_desc;

	if (crypto_hash_init(desc))
		goto clear_hash;

	if (tcp_v4_md5_hash_pseudoheader(hp, daddr, saddr, skb->len))
		goto clear_hash;
	if (tcp_md5_hash_header(hp, th))
		goto clear_hash;
	if (tcp_md5_hash_skb_data(hp, skb, th->doff << 2))
		goto clear_hash;
	if (tcp_md5_hash_key(hp, key))
		goto clear_hash;
	if (crypto_hash_final(desc, md5_hash))
		goto clear_hash;

	tcp_put_md5sig_pool();
	return 0;

clear_hash:
	tcp_put_md5sig_pool();
clear_hash_noput:
	memset(md5_hash, 0, 16);
	return 1;
}

EXPORT_SYMBOL(tcp_v4_md5_hash_skb);

static int tcp_v4_inbound_md5_hash(struct sock *sk, struct sk_buff *skb)
{
	/*
	 * This gets called for each TCP segment that arrives
	 * so we want to be efficient.
	 * We have 3 drop cases:
	 * o No MD5 hash and one expected.
	 * o MD5 hash and we're not expecting one.
	 * o MD5 hash and its wrong.
	 */
	__u8 *hash_location = NULL;
	struct tcp_md5sig_key *hash_expected;
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int genhash;
	unsigned char newhash[16];

	hash_expected = tcp_v4_md5_do_lookup(sk, iph->saddr);
	hash_location = tcp_parse_md5sig_option(th);

	/* We've parsed the options - do we have a hash? */
	if (!hash_expected && !hash_location)
		return 0;

	if (hash_expected && !hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5NOTFOUND);
		return 1;
	}

	if (!hash_expected && hash_location) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPMD5UNEXPECTED);
		return 1;
	}

	/* Okay, so this is hash_expected and hash_location -
	 * so we need to calculate the checksum.
	 */
	genhash = tcp_v4_md5_hash_skb(newhash,
				      hash_expected,
				      NULL, NULL, skb);

	if (genhash || memcmp(hash_location, newhash, 16) != 0) {
		if (net_ratelimit()) {
			printk(KERN_INFO "MD5 Hash failed for (%pI4, %d)->(%pI4, %d)%s\n",
			       &iph->saddr, ntohs(th->source),
			       &iph->daddr, ntohs(th->dest),
			       genhash ? " tcp_v4_calc_md5_hash failed" : "");
		}
		return 1;
	}
	return 0;
}

#endif

struct request_sock_ops tcp_request_sock_ops = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct tcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_rtx_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	tcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
	.syn_ack_timeout = 	tcp_syn_ack_timeout,
};

#ifdef CONFIG_TCP_MD5SIG
static const struct tcp_request_sock_ops tcp_request_sock_ipv4_ops = {
	.md5_lookup	=	tcp_v4_reqsk_md5_lookup,
	.calc_md5_hash	=	tcp_v4_md5_hash_skb,
};
#endif

static struct timewait_sock_ops tcp_timewait_sock_ops = {
	.twsk_obj_size	= sizeof(struct tcp_timewait_sock),
	.twsk_unique	= tcp_twsk_unique,
	.twsk_destructor= tcp_twsk_destructor,
};

/*
 * 服务端用来处理客户端连接请求的函数
 */
//服务器端收到SYN后，创建连接控制块request_sock。也就是收到第一步SYN的时候只是建立的连接控制块request_sock，当收到第三次ack的时候，才创建新的struct sock
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct inet_request_sock *ireq;
	struct tcp_options_received tmp_opt;
	struct request_sock *req;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	struct dst_entry *dst = NULL;
#ifdef CONFIG_SYN_COOKIES
	int want_cookie = 0; //如果启用了cookie机制，则会在第三步收到ACK的时候在tcp_v4_hnd_req中的cookie_v4_check对之前发送的ack+syn进行检查，检查过程见cookie_v4_check
#else
#define want_cookie 0 /* Argh, why doesn't gcc optimize this :( */
#endif

	/* Never answer to SYNs send to broadcast or multicast */
	/*
	 * 如果SYN段发送到广播地址或组播地址，则直接返回不作处理
	 */
	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	/*
	 * 如果SYN请求连接队列已满并且isn为零，则需做特别处理。
	 * 这里的isn就是TCP_SKB_CB(skb)->when，而TCP_SKB_CB(skb)->when
	 * 在TCP接收处理一开始就被清零，因此这里isn为零总是成立
	 */
	if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
#ifdef CONFIG_SYN_COOKIES /* 该宏默认有定义*/
		/*
		 * 如果启用了syncookies(CONFIG_SYN_COOKIES有定义)，则设置启用syncookies标志，
		 * 以便在后续的处理中使用syncookies规则来处理
		 */
		if (sysctl_tcp_syncookies) {
			want_cookie = 1;
		} else
#endif
		/*
		 * 如果没有启用syncookies，则此时不能再接收新的SYN连接请求，
		 * 只能丢弃
		 */
		goto drop;
	}

	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	/*
	 * 如果连接队列长度已达到上限且SYN请求队列中至少有一个握手过程中
	 * 没有重传过的段，则丢弃当前连接请求.
	 *  如果半连接队列中未重传的请求块数量大于1，
	 * 则表示未来可能有2个完成的连接，这些新完成
	 * 的连接要放到连接队列中，但此时连接队列已满
	 * 。如果在接收到三次握手中最后的ACK后连接队列
	 * 中没有空闲的位置，会忽略接收到的ACK包，连接
	 * 建立会推迟，所以此时最好丢掉部分新的连接请
	 * 求，空出资源以完成正在进行的连接建立过程。
	 * 还要注意，这个判断并没有考虑半连接队列是否
	 * 已满的问题。从这里可以看出，即使开启了
	 * SYN cookies机制并不意味着一定可以完成连接的建立。
	 * 
	 */
	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1)
		goto drop;

	/*
	 * 可以接收并处理连接请求，调用inet_reqsk_alloc()分配一个连接请求
	 * 块，用于保存连接请求信息，同时初始化在建立连接过程中用来发送
	 * ACK、RST段的操作集合，以便在建立连接过程中能方便地调用这些接口
	 */
	req = inet_reqsk_alloc(&tcp_request_sock_ops);
	if (!req)
		goto drop;

/*
 * 通过TCP MD5签名来保护BGP会话(RFC2385)操作
 */
#ifdef CONFIG_TCP_MD5SIG
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
#endif

	/*
	 * 清除TCP选项后初始化mss_clamp和user_mss。
	 */
	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = 536;
	tmp_opt.user_mss  = tcp_sk(sk)->rx_opt.user_mss;

	/*
	 * 解析SYN段中的TCP选项
	 */
	tcp_parse_options(skb, &tmp_opt, 0);

	/*
	 * 如果启用了syncookies，并且最近一次接收到的TCP段(即当前的skb)
	 * 不存在TCP时间戳选项，则清除已解析的TCP选项
	 */
	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	/*
	 * 初始化该连接中是否启用时间戳的选项tstamp_ok
	 */
	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;

	/*
	 * 根据接收到SYN段中的选项和序号来初始化连接请求块信息
	 */
	tcp_openreq_init(req, &tmp_opt, skb);

	/*
	 * 初始化TCP层次的连接请求信息块，包括目的地址、源地址，
	 * 并调用tcp_v4_save_options从IP层私有控制块中获取IP
	 * 选项保存到传输控制块的opt中，包括MSS、窗口扩大
	 * 因子、显式拥塞通知等
	 */
	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->no_srccheck = inet_sk(sk)->transparent;
	ireq->opt = tcp_v4_save_options(sk, skb);

	/*
	 * 如果安全检测失败，则丢弃该SYN段
	 */
	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	if (!want_cookie)
		TCP_ECN_create_request(req, tcp_hdr(skb));

	if (want_cookie) {
		/*
		 * 如果启动了syncookies，则每60秒警告一次可能受
		 * synflood攻击，同时由客户端IP地址、客户端端口、
		 * 服务器IP地址、服务器端口、客户端初始序列号
		 * 等要素经hash运算后加密得到服务端初始化序列号
		 */
#ifdef CONFIG_SYN_COOKIES
		syn_flood_warning(skb);
		req->cookie_ts = tmp_opt.tstamp_ok;
#endif
		isn = cookie_v4_init_sequence(sk, skb, &req->mss);//如果开启了syncookie选项，则需要检查收到的第三步ack和这个isn值是否一致
	} else if (!isn) {
		struct inet_peer *peer = NULL;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		/*
		 * 进入TIMEWAIT状态时，从对端信息块中获取时间戳，在新的
		 * 连接请求之前检测PAWS
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet_csk_route_req(sk, req)) != NULL &&
		    (peer = rt_get_peer((struct rtable *)dst)) != NULL &&
		    peer->v4daddr == saddr) { //当起了快速回收tw_recycle的时候，这里可能有问题，可能连接建立不上，针对TCP时间戳PAWS漏洞的代码。 见:http://blog.chinaunix.net/uid-736168-id-376061.html
                //针对TCP时间戳PAWS漏洞，造成服务器端收到SYN的时候不回收SYN+ACK，解决办法是对方不要发送时间戳选项，同时关闭tcp_timestamps见tcp_v4_conn_request
			if (get_seconds() < peer->tcp_ts_stamp + TCP_PAWS_MSL &&
			    (s32)(peer->tcp_ts - req->ts_recent) >
							TCP_PAWS_WINDOW) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		/*
		 * 未启动syncookies的情况下受到synflood攻击，则丢弃接收到的段
		 */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 (!peer || !peer->tcp_ts_stamp) &&
			 (!dst || !dst_metric(dst, RTAX_RTT))) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open request from %pI4/%u\n",
				       &saddr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		/*
		 * 由源地址、源端口号、目的地址以及目的端口计算出服务端
		 * 初始序列号
		 */
		isn = tcp_v4_init_sequence(skb);
	}
	/*
	 * 将计算得到的初始序列号存放到连接请求阶段的传输控制块中
	 */
	tcp_rsk(req)->snt_isn = isn;

	/*
	 * 调用__tcp_v4_send_synack()组织并发送SYN+ACK段给客户端；如果
	 * 启用了syncookies，则是根据序号来判断三次握手的，因此无需保存
	 * 连接请求，直接将其释放
	 */
	if (tcp_v4_send_synack(sk, req, dst) || want_cookie) //如果是cookie，则真正的tcp_request_sock在第三步ack的时候在cookie_v4_check中创建
		goto drop_and_free;

	/*
	 * 将连接请求块保存到其父传输控制块中的散列表中
	 */
	inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
drop:
	return 0;
}


int tcp_v4_conn_request1(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_extend_values tmp_ext;
	struct tcp_options_received tmp_opt;
	u8 *hash_location;
	struct request_sock *req;
	struct inet_request_sock *ireq;
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = NULL;
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
#ifdef CONFIG_SYN_COOKIES
	int want_cookie = 0;
#else
#define want_cookie 0 /* Argh, why doesn't gcc optimize this :( */
#endif

	/* Never answer to SYNs send to broadcast or multicast */
	if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
		goto drop;

	/* TW buckets are converted to open requests without
	 * limitations, they conserve resources and peer is
	 * evidently real one.
	 */
	if (inet_csk_reqsk_queue_is_full(sk) && !isn) {
#ifdef CONFIG_SYN_COOKIES
		if (sysctl_tcp_syncookies) {
			want_cookie = 1;
		} else
#endif
		goto drop;
	}

	/* Accept backlog is full. If we have already queued enough
	 * of warm entries in syn queue, drop request. It is better than
	 * clogging syn queue with openreqs with exponentially increasing
	 * timeout.
	 */
	if (sk_acceptq_is_full(sk) && inet_csk_reqsk_queue_young(sk) > 1)
		goto drop;

	req = inet_reqsk_alloc(&tcp_request_sock_ops);
	if (!req)
		goto drop;

#ifdef CONFIG_TCP_MD5SIG
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
#endif

	tcp_clear_options(&tmp_opt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss  = tp->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

	if (tmp_opt.cookie_plus > 0 &&
	    tmp_opt.saw_tstamp &&
	    !tp->rx_opt.cookie_out_never &&
	    (sysctl_tcp_cookie_size > 0 ||
	     (tp->cookie_values != NULL &&
	      tp->cookie_values->cookie_desired > 0))) {
		u8 *c;
		u32 *mess = &tmp_ext.cookie_bakery[COOKIE_DIGEST_WORDS];
		int l = tmp_opt.cookie_plus - TCPOLEN_COOKIE_BASE;

		if (tcp_cookie_generator(&tmp_ext.cookie_bakery[0]) != 0)
			goto drop_and_release;

		/* Secret recipe starts with IP addresses */
		*mess++ ^= (__force u32)daddr;
		*mess++ ^= (__force u32)saddr;

		/* plus variable length Initiator Cookie */
		c = (u8 *)mess;
		while (l-- > 0)
			*c++ ^= *hash_location++;

#ifdef CONFIG_SYN_COOKIES
		want_cookie = 0;	/* not our kind of cookie */
#endif
		tmp_ext.cookie_out_never = 0; /* false */
		tmp_ext.cookie_plus = tmp_opt.cookie_plus;
	} else if (!tp->rx_opt.cookie_in_always) {
		/* redundant indications, but ensure initialization. */
		tmp_ext.cookie_out_never = 1; /* true */
		tmp_ext.cookie_plus = 0;
	} else {
		goto drop_and_release;
	}
	tmp_ext.cookie_in_always = tp->rx_opt.cookie_in_always;

	if (want_cookie && !tmp_opt.saw_tstamp)
		tcp_clear_options(&tmp_opt);

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->no_srccheck = inet_sk(sk)->transparent;
	ireq->opt = tcp_v4_save_options(sk, skb);

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	if (!want_cookie)
		TCP_ECN_create_request(req, tcp_hdr(skb));

	if (want_cookie) {
#ifdef CONFIG_SYN_COOKIES
		syn_flood_warning(skb);
		req->cookie_ts = tmp_opt.tstamp_ok;
#endif
		isn = cookie_v4_init_sequence(sk, skb, &req->mss);
	} else if (!isn) {
		struct inet_peer *peer = NULL;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet_csk_route_req(sk, req)) != NULL &&
		    (peer = rt_get_peer((struct rtable *)dst)) != NULL &&
		    peer->v4daddr == saddr) {
			if ((u32)get_seconds() - peer->tcp_ts_stamp < TCP_PAWS_MSL &&
			    (s32)(peer->tcp_ts - req->ts_recent) >
							TCP_PAWS_WINDOW) {
				NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 (!peer || !peer->tcp_ts_stamp) &&
			 (!dst || !dst_metric(dst, RTAX_RTT))) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: drop open request from %pI4/%u\n",
				       &saddr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		isn = tcp_v4_init_sequence(skb);
	}
	tcp_rsk(req)->snt_isn = isn;

	if (tcp_v4_send_synack(sk, dst, req,
			       (struct request_values *)&tmp_ext) ||
	    want_cookie)
		goto drop_and_free;

	inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
	return 0;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
drop:
	return 0;
}


/*
 * The three way handshake has completed - we got a valid synack -
 * now create the new socket.
 */
 //收到TCP连接第三步的ACK后，创建一个新的struct sock,也叫'子'sk
struct sock *tcp_v4_syn_recv_sock(struct sock *sk, struct sk_buff *skb,
				  struct request_sock *req,
				  struct dst_entry *dst)
{
	struct inet_request_sock *ireq;
	struct inet_sock *newinet;
	struct tcp_sock *newtp;
	struct sock *newsk;
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_md5sig_key *key;
#endif

	if (sk_acceptq_is_full(sk))
		goto exit_overflow;

	if (!dst && (dst = inet_csk_route_req(sk, req)) == NULL)
		goto exit;

	newsk = tcp_create_openreq_child(sk, req, skb);
	if (!newsk)
		goto exit;

	newsk->sk_gso_type = SKB_GSO_TCPV4;
	sk_setup_caps(newsk, dst);

	newtp		      = tcp_sk(newsk);
	newinet		      = inet_sk(newsk);
	ireq		      = inet_rsk(req);
	newinet->inet_daddr   = ireq->rmt_addr;
	newinet->inet_rcv_saddr = ireq->loc_addr;
	newinet->inet_saddr	      = ireq->loc_addr;
	newinet->opt	      = ireq->opt;
	ireq->opt	      = NULL;
	newinet->mc_index     = inet_iif(skb);
	newinet->mc_ttl	      = ip_hdr(skb)->ttl;
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (newinet->opt)
		inet_csk(newsk)->icsk_ext_hdr_len = newinet->opt->optlen;
	newinet->inet_id = newtp->write_seq ^ jiffies;

	tcp_mtup_init(newsk);
	tcp_sync_mss(newsk, dst_mtu(dst));
	newtp->advmss = dst_metric(dst, RTAX_ADVMSS);
	if (tcp_sk(sk)->rx_opt.user_mss &&
	    tcp_sk(sk)->rx_opt.user_mss < newtp->advmss)
		newtp->advmss = tcp_sk(sk)->rx_opt.user_mss;

	tcp_initialize_rcv_mss(newsk);

#ifdef CONFIG_TCP_MD5SIG
	/* Copy over the MD5 key from the original socket */
	key = tcp_v4_md5_do_lookup(sk, newinet->inet_daddr);
	if (key != NULL) {
		/*
		 * We're using one, so create a matching key
		 * on the newsk structure. If we fail to get
		 * memory, then we end up not copying the key
		 * across. Shucks.
		 */
		char *newkey = kmemdup(key->key, key->keylen, GFP_ATOMIC);
		if (newkey != NULL)
			tcp_v4_md5_do_add(newsk, newinet->inet_daddr,
					  newkey, key->keylen);
		sk_nocaps_add(newsk, NETIF_F_GSO_MASK);
	}
#endif

	__inet_hash_nolisten(newsk, NULL);
	__inet_inherit_port(sk, newsk);

	return newsk;

exit_overflow:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
exit:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_LISTENDROPS);
	dst_release(dst);
	return NULL;
}
/*
 * 用来处理作为建立连接三次握手中最后一次握手的ACK段，处理过程如下:
 *  1. 在请求连接散列表中查找对应的请求连接块。
 *  2. 如果找到，则根据TCP段标志，ACK或RST或SYN，作相应的处理，
 *     如果是ACK段则完成连接建立
 *  3. 如果查找未果，则还需在ehash散列表中查找对应传输控制块，
 *     并作相应的处理。如果还是查找不到则返回，由tcp_rcv_state_process
 *     处理
 */
static struct sock *tcp_v4_hnd_req(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);
	struct sock *nsk;
	struct request_sock **prev;
	/* Find possible connection requests. */
	/*
	 * 如果根据源端口、源地址、目的地址在"父"传输控制块的连接请求散列表
	 * 中查找相应的连接请求块成功，则说明三次握手中的前两次已经完成，
	 * 接下来进行第三次握手的确认
	 */
	//这里面搜索的是inet_connection_sock->icsk_accept_queue中的半连接syn_table hash表
	struct request_sock *req = inet_csk_search_req(sk, &prev, th->source,
						       iph->saddr, iph->daddr);
	if (req)
		return tcp_check_req(sk, skb, req, prev);
    
	 /*
	 * 如果传输控制块不在连接请求散列表中，则有可能在ehash散列表中，
	 * 因此需要在ehash散列表中查找
	 */
    //这里面搜索的是已经三次握手成功的连接控制块
	nsk = inet_lookup_established(sock_net(sk), &tcp_hashinfo, iph->saddr,
			th->source, iph->daddr, th->dest, inet_iif(skb));

    /*
	 * 在ehash散列表中查找成功的情况下，如果该传输控制块不处于
	 * TIME_WAIT状态，返回该传输控制块；否则说明接收到的段无效，因为连接都已经建立起来了，不应该收到三部握手中的报文
	 * 返回NULL表示丢弃该段
	 */
	if (nsk) {
		if (nsk->sk_state != TCP_TIME_WAIT) {
			bh_lock_sock(nsk);
			return nsk;
		}
		inet_twsk_put(inet_twsk(nsk));
		return NULL;
	}

#ifdef CONFIG_SYN_COOKIES
	if (!th->rst && !th->syn && th->ack)
		sk = cookie_v4_check(sk, skb, &(IPCB(skb)->opt));
#endif
	return sk;
}

/*
 * 用于TCP段接收校验的初始化，主要是对伪首部进行校验和的计算。
 * 当然也有例外，如果校验和由硬件完成，则只对伪首部进行校验
 * 检测。对于全长不超过76B的TCP包，则直接进行伪首部和全包校验
 *///这是TCP输出的时候的校验和tcp_v4_send_check, TCP输入的时候计算校验和用的tcp_v4_checksum_init
static __sum16 tcp_v4_checksum_init(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);

    /*
	 * 如果TCP包本身的校验已经由硬件完成，则只对伪首部
	 * 进行校验
	 */
	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!tcp_v4_check(skb->len, iph->saddr,
				  iph->daddr, skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			return 0;
		}
	}

    /*
	 * 对于用软件完成校验和的操作，首先生成伪首部
	 * 的部分累加和
	 */ //TCP UDP伪首部校验
	skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
				       skb->len, IPPROTO_TCP, 0);

    /*
	 * 对于全长不超过76B的TCP包直接进行校验。其他的包，
	 * 在后续操作中完成全包校验和检测
	 */
	if (skb->len <= 76) {
		return __skb_checksum_complete(skb);
	}
	return 0;
}


/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 *//*
 * TCP传输层接收到段之后，经过了简单的
 * 校验，并确定接收处理该段的传输控制
 * 块之后，除非处于FIN_WAIT_2或TIME_WAIT状态，
 * 否则都会调用tcp_v4_do_rcv()作具体的处理
 */
int tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *rsk;
#ifdef CONFIG_TCP_MD5SIG
	/*
	 * We really want to reject the packet as early as possible
	 * if:
	 *  o We're expecting an MD5'd packet and this is no MD5 tcp option
	 *  o There is an MD5 option and we're not expecting one
	 */
	if (tcp_v4_inbound_md5_hash(sk, skb))
		goto discard;
#endif

	if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */ 
		sock_rps_save_rxhash(sk, skb->rxhash);
		TCP_CHECK_TIMER(sk);
		if (tcp_rcv_established(sk, skb, tcp_hdr(skb), skb->len)) {
			rsk = sk;
			goto reset;
		}
		TCP_CHECK_TIMER(sk);
		return 0;
	}

	if (skb->len < tcp_hdrlen(skb) || tcp_checksum_complete(skb))
		goto csum_err;

	if (sk->sk_state == TCP_LISTEN) { //说明收到的是三次握手第一步SYN或者第三步ACK,这里是服务器端的情况
		struct sock *nsk = tcp_v4_hnd_req(sk, skb);
		if (!nsk)
			goto discard;

		if (nsk != sk) {//如果是第一次握手的SYN，这里的nsk应该是'父'sk, 如果这里是三次握手的第三步ACK，则这里的nsk是‘子'sk
			if (tcp_child_process(sk, nsk, skb)) { //这里面还是会调用tcp_rcv_state_process
				rsk = nsk;
				goto reset;
			}
			return 0; //如果是握手的第三步，这里直接退出
		} //如果是三次握手中的第一步SYN，则继续后面的操作
	} else
		sock_rps_save_rxhash(sk, skb->rxhash);

    //走到这里说明只能是客户端收到SYN+ACK,或者是服务器端收到SYN
	TCP_CHECK_TIMER(sk);
	if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
		rsk = sk;
		goto reset;
	}
	TCP_CHECK_TIMER(sk);
	return 0;

reset:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	/* Be careful here. If this function gets more complicated and
	 * gcc suffers from register pressure on the x86, sk (in %ebx)
	 * might be destroyed here. This current version compiles correctly,
	 * but you have been warned.
	 */
	return 0;

csum_err:
	TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_INERRS);
	goto discard;
}

/*
 *	From tcp_input.c
 */
//tcp_protocol
int tcp_v4_rcv(struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct tcphdr *th;
	struct sock *sk;
	int ret;
	struct net *net = dev_net(skb->dev);

	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	/* Count it even if it's bad */
	TCP_INC_STATS_BH(net, TCP_MIB_INSEGS);

	if (!pskb_may_pull(skb, sizeof(struct tcphdr)))
		goto discard_it;

	th = tcp_hdr(skb);

	if (th->doff < sizeof(struct tcphdr) / 4)
		goto bad_packet;
	if (!pskb_may_pull(skb, th->doff * 4))
		goto discard_it;

	/* An explanation is required here, I think.
	 * Packet length and doff are validated by header prediction,
	 * provided case of th->doff==0 is eliminated.
	 * So, we defer the checks. */
	if (!skb_csum_unnecessary(skb) && tcp_v4_checksum_init(skb))
		goto bad_packet;

	th = tcp_hdr(skb);
	iph = ip_hdr(skb);
	TCP_SKB_CB(skb)->seq = ntohl(th->seq);
	TCP_SKB_CB(skb)->end_seq = (TCP_SKB_CB(skb)->seq + th->syn + th->fin +
				    skb->len - th->doff * 4);
	TCP_SKB_CB(skb)->ack_seq = ntohl(th->ack_seq);
	TCP_SKB_CB(skb)->when	 = 0;
	TCP_SKB_CB(skb)->flags	 = iph->tos;
	TCP_SKB_CB(skb)->sacked	 = 0;

	sk = __inet_lookup_skb(&tcp_hashinfo, skb, th->source, th->dest);
	if (!sk)
		goto no_tcp_socket;

process:
	if (sk->sk_state == TCP_TIME_WAIT)
		goto do_time_wait;

	if (unlikely(iph->ttl < inet_sk(sk)->min_ttl)) {
		NET_INC_STATS_BH(net, LINUX_MIB_TCPMINTTLDROP);
		goto discard_and_relse;
	}

	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;
	nf_reset(skb);

	if (sk_filter(sk, skb))
		goto discard_and_relse;

	skb->dev = NULL;

	bh_lock_sock_nested(sk);
	ret = 0;
	if (!sock_owned_by_user(sk)) {
#ifdef CONFIG_NET_DMA
		struct tcp_sock *tp = tcp_sk(sk);
		if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
			tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);
		if (tp->ucopy.dma_chan)
			ret = tcp_v4_do_rcv(sk, skb);
		else
#endif
		{
			if (!tcp_prequeue(sk, skb))
				ret = tcp_v4_do_rcv(sk, skb);
		}
	} else if (unlikely(sk_add_backlog(sk, skb))) {
		bh_unlock_sock(sk);
		NET_INC_STATS_BH(net, LINUX_MIB_TCPBACKLOGDROP);
		goto discard_and_relse;
	}
	bh_unlock_sock(sk);

	sock_put(sk);

	return ret;

no_tcp_socket:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
bad_packet:
		TCP_INC_STATS_BH(net, TCP_MIB_INERRS);
	} else {
		tcp_v4_send_reset(NULL, skb);
	}

discard_it:
	/* Discard frame. */
	kfree_skb(skb);
	return 0;

discard_and_relse:
	sock_put(sk);
	goto discard_it;

do_time_wait:
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}

	if (skb->len < (th->doff << 2) || tcp_checksum_complete(skb)) {
		TCP_INC_STATS_BH(net, TCP_MIB_INERRS);
		inet_twsk_put(inet_twsk(sk));
		goto discard_it;
	}
	switch (tcp_timewait_state_process(inet_twsk(sk), skb, th)) {
	case TCP_TW_SYN: {
		struct sock *sk2 = inet_lookup_listener(dev_net(skb->dev),
							&tcp_hashinfo,
							iph->daddr, th->dest,
							inet_iif(skb));
		if (sk2) {
			inet_twsk_deschedule(inet_twsk(sk), &tcp_death_row);
			inet_twsk_put(inet_twsk(sk));
			sk = sk2;
			goto process;
		}
		/* Fall through to ACK */
	}
	case TCP_TW_ACK:
		tcp_v4_timewait_ack(sk, skb);
		break;
	case TCP_TW_RST:
		goto no_tcp_socket;
	case TCP_TW_SUCCESS:;
	}
	goto discard_it;
}

/* VJ's idea. Save last timestamp seen from this destination
 * and hold it at least for normal timewait interval to use for duplicate
 * segment detection in subsequent connections, before they enter synchronized
 * state.
 */

int tcp_v4_remember_stamp(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct rtable *rt = (struct rtable *)__sk_dst_get(sk);
	struct inet_peer *peer = NULL;
	int release_it = 0;

	if (!rt || rt->rt_dst != inet->inet_daddr) {
		peer = inet_getpeer(inet->inet_daddr, 1);
		release_it = 1;
	} else {
		if (!rt->peer)
			rt_bind_peer(rt, 1);
		peer = rt->peer;
	}

	if (peer) {
		if ((s32)(peer->tcp_ts - tp->rx_opt.ts_recent) <= 0 ||
		    ((u32)get_seconds() - peer->tcp_ts_stamp > TCP_PAWS_MSL &&
		     peer->tcp_ts_stamp <= (u32)tp->rx_opt.ts_recent_stamp)) {
			peer->tcp_ts_stamp = (u32)tp->rx_opt.ts_recent_stamp;
			peer->tcp_ts = tp->rx_opt.ts_recent;
		}
		if (release_it)
			inet_putpeer(peer);
		return 1;
	}

	return 0;
}

int tcp_v4_tw_remember_stamp(struct inet_timewait_sock *tw)
{
	struct inet_peer *peer = inet_getpeer(tw->tw_daddr, 1);

	if (peer) {
		const struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);

		if ((s32)(peer->tcp_ts - tcptw->tw_ts_recent) <= 0 ||
		    ((u32)get_seconds() - peer->tcp_ts_stamp > TCP_PAWS_MSL &&
		     peer->tcp_ts_stamp <= (u32)tcptw->tw_ts_recent_stamp)) {
			peer->tcp_ts_stamp = (u32)tcptw->tw_ts_recent_stamp;
			peer->tcp_ts	   = tcptw->tw_ts_recent;
		}
		inet_putpeer(peer);
		return 1;
	}

	return 0;
}

//在tcp_prot->init中被赋值给inet_connection_sock->icsk_af_ops
const struct inet_connection_sock_af_ops ipv4_specific = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = tcp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = tcp_v4_conn_request,
	.syn_recv_sock	   = tcp_v4_syn_recv_sock,
	.remember_stamp	   = tcp_v4_remember_stamp,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ip_setsockopt,
	.getsockopt	   = ip_getsockopt,
	.addr2sockaddr	   = inet_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in),
	.bind_conflict	   = inet_csk_bind_conflict,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ip_setsockopt,
	.compat_getsockopt = compat_ip_getsockopt,
#endif
};

#ifdef CONFIG_TCP_MD5SIG
static const struct tcp_sock_af_ops tcp_sock_ipv4_specific = {
	.md5_lookup		= tcp_v4_md5_lookup,
	.calc_md5_hash		= tcp_v4_md5_hash_skb,
	.md5_add		= tcp_v4_md5_add_func,
	.md5_parse		= tcp_v4_parse_md5_keys,
};
#endif

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 它主要是对tcp_sock和inet_connection_sock进行一些初始化；
 */
static int tcp_v4_init_sock(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_head_init(&tp->out_of_order_queue);
	tcp_init_xmit_timers(sk);
	tcp_prequeue_init(tp);

	icsk->icsk_rto = TCP_TIMEOUT_INIT;
	tp->mdev = TCP_TIMEOUT_INIT;

	/* So many TCP implementations out there (incorrectly) count the
	 * initial SYN frame in their delayed-ACK and congestion control
	 * algorithms that we must have the following bandaid to talk
	 * efficiently to them.  -DaveM
	 */
	tp->snd_cwnd = 2;

	/* See draft-stevens-tcpca-spec-01 for discussion of the
	 * initialization of these values.
	 */
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_clamp = ~0;
	tp->mss_cache = TCP_MSS_DEFAULT;

	tp->reordering = sysctl_tcp_reordering;
	icsk->icsk_ca_ops = &tcp_init_congestion_ops;

	sk->sk_state = TCP_CLOSE;

	sk->sk_write_space = sk_stream_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	icsk->icsk_af_ops = &ipv4_specific;
	icsk->icsk_sync_mss = tcp_sync_mss;
#ifdef CONFIG_TCP_MD5SIG
	tp->af_specific = &tcp_sock_ipv4_specific;
#endif

	/* TCP Cookie Transactions */
	if (sysctl_tcp_cookie_size > 0) {
		/* Default, cookies without s_data_payload. */
		tp->cookie_values =
			kzalloc(sizeof(*tp->cookie_values),
				sk->sk_allocation);
		if (tp->cookie_values != NULL)
			kref_init(&tp->cookie_values->kref);
	}
	/* Presumed zeroed, in order of appearance:
	 *	cookie_in_always, cookie_out_never,
	 *	s_data_constant, s_data_in, s_data_out
	 */
	sk->sk_sndbuf = sysctl_tcp_wmem[1];
	sk->sk_rcvbuf = sysctl_tcp_rmem[1];

	local_bh_disable();
	percpu_counter_inc(&tcp_sockets_allocated);
	local_bh_enable();

	return 0;
}

void tcp_v4_destroy_sock(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tcp_clear_xmit_timers(sk);

	tcp_cleanup_congestion_control(sk);

	/* Cleanup up the write buffer. */
	tcp_write_queue_purge(sk);

	/* Cleans up our, hopefully empty, out_of_order_queue. */
	__skb_queue_purge(&tp->out_of_order_queue);

#ifdef CONFIG_TCP_MD5SIG
	/* Clean up the MD5 key list, if any */
	if (tp->md5sig_info) {
		tcp_v4_clear_md5_list(sk);
		kfree(tp->md5sig_info);
		tp->md5sig_info = NULL;
	}
#endif

#ifdef CONFIG_NET_DMA
	/* Cleans up our sk_async_wait_queue */
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	/* Clean prequeue, it must be empty really */
	__skb_queue_purge(&tp->ucopy.prequeue);

	/* Clean up a referenced TCP bind bucket. */
	if (inet_csk(sk)->icsk_bind_hash)
		inet_put_port(sk);

	/*
	 * If sendmsg cached page exists, toss it.
	 */
	if (sk->sk_sndmsg_page) {
		__free_page(sk->sk_sndmsg_page);
		sk->sk_sndmsg_page = NULL;
	}

	/* TCP Cookie Transactions */
	if (tp->cookie_values != NULL) {
		kref_put(&tp->cookie_values->kref,
			 tcp_cookie_values_release);
		tp->cookie_values = NULL;
	}

	percpu_counter_dec(&tcp_sockets_allocated);
}

EXPORT_SYMBOL(tcp_v4_destroy_sock);

#ifdef CONFIG_PROC_FS
/* Proc filesystem TCP sock list dumping. */

static inline struct inet_timewait_sock *tw_head(struct hlist_nulls_head *head)
{
	return hlist_nulls_empty(head) ? NULL :
		list_entry(head->first, struct inet_timewait_sock, tw_node);
}

static inline struct inet_timewait_sock *tw_next(struct inet_timewait_sock *tw)
{
	return !is_a_nulls(tw->tw_node.next) ?
		hlist_nulls_entry(tw->tw_node.next, typeof(*tw), tw_node) : NULL;
}

static void *listening_get_next(struct seq_file *seq, void *cur)
{
	struct inet_connection_sock *icsk;
	struct hlist_nulls_node *node;
	struct sock *sk = cur;
	struct inet_listen_hashbucket *ilb;
	struct tcp_iter_state *st = seq->private;
	struct net *net = seq_file_net(seq);

	if (!sk) {
		st->bucket = 0;
		ilb = &tcp_hashinfo.listening_hash[0];
		spin_lock_bh(&ilb->lock);
		sk = sk_nulls_head(&ilb->head);
		goto get_sk;
	}
	ilb = &tcp_hashinfo.listening_hash[st->bucket];
	++st->num;

	if (st->state == TCP_SEQ_STATE_OPENREQ) {
		struct request_sock *req = cur;

		icsk = inet_csk(st->syn_wait_sk);
		req = req->dl_next;
		while (1) {
			while (req) {
				if (req->rsk_ops->family == st->family) {
					cur = req;
					goto out;
				}
				req = req->dl_next;
			}
			if (++st->sbucket >= icsk->icsk_accept_queue.listen_opt->nr_table_entries)
				break;
get_req:
			req = icsk->icsk_accept_queue.listen_opt->syn_table[st->sbucket];
		}
		sk	  = sk_next(st->syn_wait_sk);
		st->state = TCP_SEQ_STATE_LISTENING;
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
	} else {
		icsk = inet_csk(sk);
		read_lock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		if (reqsk_queue_len(&icsk->icsk_accept_queue))
			goto start_req;
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		sk = sk_next(sk);
	}
get_sk:
	sk_nulls_for_each_from(sk, node) {
		if (sk->sk_family == st->family && net_eq(sock_net(sk), net)) {
			cur = sk;
			goto out;
		}
		icsk = inet_csk(sk);
		read_lock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		if (reqsk_queue_len(&icsk->icsk_accept_queue)) {
start_req:
			st->uid		= sock_i_uid(sk);
			st->syn_wait_sk = sk;
			st->state	= TCP_SEQ_STATE_OPENREQ;
			st->sbucket	= 0;
			goto get_req;
		}
		read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
	}
	spin_unlock_bh(&ilb->lock);
	if (++st->bucket < INET_LHTABLE_SIZE) {
		ilb = &tcp_hashinfo.listening_hash[st->bucket];
		spin_lock_bh(&ilb->lock);
		sk = sk_nulls_head(&ilb->head);
		goto get_sk;
	}
	cur = NULL;
out:
	return cur;
}

static void *listening_get_idx(struct seq_file *seq, loff_t *pos)
{
	void *rc = listening_get_next(seq, NULL);

	while (rc && *pos) {
		rc = listening_get_next(seq, rc);
		--*pos;
	}
	return rc;
}

static inline int empty_bucket(struct tcp_iter_state *st)
{
	return hlist_nulls_empty(&tcp_hashinfo.ehash[st->bucket].chain) &&
		hlist_nulls_empty(&tcp_hashinfo.ehash[st->bucket].twchain);
}

static void *established_get_first(struct seq_file *seq)
{
	struct tcp_iter_state *st = seq->private;
	struct net *net = seq_file_net(seq);
	void *rc = NULL;

	for (st->bucket = 0; st->bucket <= tcp_hashinfo.ehash_mask; ++st->bucket) {
		struct sock *sk;
		struct hlist_nulls_node *node;
		struct inet_timewait_sock *tw;
		spinlock_t *lock = inet_ehash_lockp(&tcp_hashinfo, st->bucket);

		/* Lockless fast path for the common case of empty buckets */
		if (empty_bucket(st))
			continue;

		spin_lock_bh(lock);
		sk_nulls_for_each(sk, node, &tcp_hashinfo.ehash[st->bucket].chain) {
			if (sk->sk_family != st->family ||
			    !net_eq(sock_net(sk), net)) {
				continue;
			}
			rc = sk;
			goto out;
		}
		st->state = TCP_SEQ_STATE_TIME_WAIT;
		inet_twsk_for_each(tw, node,
				   &tcp_hashinfo.ehash[st->bucket].twchain) {
			if (tw->tw_family != st->family ||
			    !net_eq(twsk_net(tw), net)) {
				continue;
			}
			rc = tw;
			goto out;
		}
		spin_unlock_bh(lock);
		st->state = TCP_SEQ_STATE_ESTABLISHED;
	}
out:
	return rc;
}

static void *established_get_next(struct seq_file *seq, void *cur)
{
	struct sock *sk = cur;
	struct inet_timewait_sock *tw;
	struct hlist_nulls_node *node;
	struct tcp_iter_state *st = seq->private;
	struct net *net = seq_file_net(seq);

	++st->num;

	if (st->state == TCP_SEQ_STATE_TIME_WAIT) {
		tw = cur;
		tw = tw_next(tw);
get_tw:
		while (tw && (tw->tw_family != st->family || !net_eq(twsk_net(tw), net))) {
			tw = tw_next(tw);
		}
		if (tw) {
			cur = tw;
			goto out;
		}
		spin_unlock_bh(inet_ehash_lockp(&tcp_hashinfo, st->bucket));
		st->state = TCP_SEQ_STATE_ESTABLISHED;

		/* Look for next non empty bucket */
		while (++st->bucket <= tcp_hashinfo.ehash_mask &&
				empty_bucket(st))
			;
		if (st->bucket > tcp_hashinfo.ehash_mask)
			return NULL;

		spin_lock_bh(inet_ehash_lockp(&tcp_hashinfo, st->bucket));
		sk = sk_nulls_head(&tcp_hashinfo.ehash[st->bucket].chain);
	} else
		sk = sk_nulls_next(sk);

	sk_nulls_for_each_from(sk, node) {
		if (sk->sk_family == st->family && net_eq(sock_net(sk), net))
			goto found;
	}

	st->state = TCP_SEQ_STATE_TIME_WAIT;
	tw = tw_head(&tcp_hashinfo.ehash[st->bucket].twchain);
	goto get_tw;
found:
	cur = sk;
out:
	return cur;
}

static void *established_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc = established_get_first(seq);

	while (rc && pos) {
		rc = established_get_next(seq, rc);
		--pos;
	}
	return rc;
}

static void *tcp_get_idx(struct seq_file *seq, loff_t pos)
{
	void *rc;
	struct tcp_iter_state *st = seq->private;

	st->state = TCP_SEQ_STATE_LISTENING;
	rc	  = listening_get_idx(seq, &pos);

	if (!rc) {
		st->state = TCP_SEQ_STATE_ESTABLISHED;
		rc	  = established_get_idx(seq, pos);
	}

	return rc;
}

static void *tcp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct tcp_iter_state *st = seq->private;
	st->state = TCP_SEQ_STATE_LISTENING;
	st->num = 0;
	return *pos ? tcp_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *tcp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	void *rc = NULL;
	struct tcp_iter_state *st;

	if (v == SEQ_START_TOKEN) {
		rc = tcp_get_idx(seq, 0);
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
	case TCP_SEQ_STATE_LISTENING:
		rc = listening_get_next(seq, v);
		if (!rc) {
			st->state = TCP_SEQ_STATE_ESTABLISHED;
			rc	  = established_get_first(seq);
		}
		break;
	case TCP_SEQ_STATE_ESTABLISHED:
	case TCP_SEQ_STATE_TIME_WAIT:
		rc = established_get_next(seq, v);
		break;
	}
out:
	++*pos;
	return rc;
}

static void tcp_seq_stop(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_OPENREQ:
		if (v) {
			struct inet_connection_sock *icsk = inet_csk(st->syn_wait_sk);
			read_unlock_bh(&icsk->icsk_accept_queue.syn_wait_lock);
		}
	case TCP_SEQ_STATE_LISTENING:
		if (v != SEQ_START_TOKEN)
			spin_unlock_bh(&tcp_hashinfo.listening_hash[st->bucket].lock);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
	case TCP_SEQ_STATE_ESTABLISHED:
		if (v)
			spin_unlock_bh(inet_ehash_lockp(&tcp_hashinfo, st->bucket));
		break;
	}
}

static int tcp_seq_open(struct inode *inode, struct file *file)
{
	struct tcp_seq_afinfo *afinfo = PDE(inode)->data;
	struct tcp_iter_state *s;
	int err;

	err = seq_open_net(inode, file, &afinfo->seq_ops,
			  sizeof(struct tcp_iter_state));
	if (err < 0)
		return err;

	s = ((struct seq_file *)file->private_data)->private;
	s->family		= afinfo->family;
	return 0;
}

int tcp_proc_register(struct net *net, struct tcp_seq_afinfo *afinfo)
{
	int rc = 0;
	struct proc_dir_entry *p;

	afinfo->seq_fops.open		= tcp_seq_open;
	afinfo->seq_fops.read		= seq_read;
	afinfo->seq_fops.llseek		= seq_lseek;
	afinfo->seq_fops.release	= seq_release_net;

	afinfo->seq_ops.start		= tcp_seq_start;
	afinfo->seq_ops.next		= tcp_seq_next;
	afinfo->seq_ops.stop		= tcp_seq_stop;

	p = proc_create_data(afinfo->name, S_IRUGO, net->proc_net,
			     &afinfo->seq_fops, afinfo);
	if (!p)
		rc = -ENOMEM;
	return rc;
}

void tcp_proc_unregister(struct net *net, struct tcp_seq_afinfo *afinfo)
{
	proc_net_remove(net, afinfo->name);
}

static void get_openreq4(struct sock *sk, struct request_sock *req,
			 struct seq_file *f, int i, int uid, int *len)
{
	const struct inet_request_sock *ireq = inet_rsk(req);
	int ttd = req->expires - jiffies;

	seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %u %d %p%n",
		i,
		ireq->loc_addr,
		ntohs(inet_sk(sk)->inet_sport),
		ireq->rmt_addr,
		ntohs(ireq->rmt_port),
		TCP_SYN_RECV,
		0, 0, /* could print option size, but that is af dependent. */
		1,    /* timers active (only the expire timer) */
		jiffies_to_clock_t(ttd),
		req->retrans,
		uid,
		0,  /* non standard timer */
		0, /* open_requests have no inode */
		atomic_read(&sk->sk_refcnt),
		req,
		len);
}

static void get_tcp4_sock(struct sock *sk, struct seq_file *f, int i, int *len)
{
	int timer_active;
	unsigned long timer_expires;
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	__be32 dest = inet->inet_daddr;
	__be32 src = inet->inet_rcv_saddr;
	__u16 destp = ntohs(inet->inet_dport);
	__u16 srcp = ntohs(inet->inet_sport);
	int rx_queue;

	if (icsk->icsk_pending == ICSK_TIME_RETRANS) {
		timer_active	= 1;
		timer_expires	= icsk->icsk_timeout;
	} else if (icsk->icsk_pending == ICSK_TIME_PROBE0) {
		timer_active	= 4;
		timer_expires	= icsk->icsk_timeout;
	} else if (timer_pending(&sk->sk_timer)) {
		timer_active	= 2;
		timer_expires	= sk->sk_timer.expires;
	} else {
		timer_active	= 0;
		timer_expires = jiffies;
	}

	if (sk->sk_state == TCP_LISTEN)
		rx_queue = sk->sk_ack_backlog;
	else
		/*
		 * because we dont lock socket, we might find a transient negative value
		 */
		rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);

	seq_printf(f, "%4d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX "
			"%08X %5d %8d %lu %d %p %lu %lu %u %u %d%n",
		i, src, srcp, dest, destp, sk->sk_state,
		tp->write_seq - tp->snd_una,
		rx_queue,
		timer_active,
		jiffies_to_clock_t(timer_expires - jiffies),
		icsk->icsk_retransmits,
		sock_i_uid(sk),
		icsk->icsk_probes_out,
		sock_i_ino(sk),
		atomic_read(&sk->sk_refcnt), sk,
		jiffies_to_clock_t(icsk->icsk_rto),
		jiffies_to_clock_t(icsk->icsk_ack.ato),
		(icsk->icsk_ack.quick << 1) | icsk->icsk_ack.pingpong,
		tp->snd_cwnd,
		tcp_in_initial_slowstart(tp) ? -1 : tp->snd_ssthresh,
		len);
}

static void get_timewait4_sock(struct inet_timewait_sock *tw,
			       struct seq_file *f, int i, int *len)
{
	__be32 dest, src;
	__u16 destp, srcp;
	int ttd = tw->tw_ttd - jiffies;

	if (ttd < 0)
		ttd = 0;

	dest  = tw->tw_daddr;
	src   = tw->tw_rcv_saddr;
	destp = ntohs(tw->tw_dport);
	srcp  = ntohs(tw->tw_sport);

	seq_printf(f, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %d %d %p%n",
		i, src, srcp, dest, destp, tw->tw_substate, 0, 0,
		3, jiffies_to_clock_t(ttd), 0, 0, 0, 0,
		atomic_read(&tw->tw_refcnt), tw, len);
}

#define TMPSZ 150

static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	int len;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
			   "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;

	switch (st->state) {
	case TCP_SEQ_STATE_LISTENING:
	case TCP_SEQ_STATE_ESTABLISHED:
		get_tcp4_sock(v, seq, st->num, &len);
		break;
	case TCP_SEQ_STATE_OPENREQ:
		get_openreq4(st->syn_wait_sk, v, seq, st->num, st->uid, &len);
		break;
	case TCP_SEQ_STATE_TIME_WAIT:
		get_timewait4_sock(v, seq, st->num, &len);
		break;
	}
	seq_printf(seq, "%*s\n", TMPSZ - 1 - len, "");
out:
	return 0;
}

static struct tcp_seq_afinfo tcp4_seq_afinfo = {
	.name		= "tcp",
	.family		= AF_INET,
	.seq_fops	= {
		.owner		= THIS_MODULE,
	},
	.seq_ops	= {
		.show		= tcp4_seq_show,
	},
};

static int __net_init tcp4_proc_init_net(struct net *net)
{
	return tcp_proc_register(net, &tcp4_seq_afinfo);
}

static void __net_exit tcp4_proc_exit_net(struct net *net)
{
	tcp_proc_unregister(net, &tcp4_seq_afinfo);
}

static struct pernet_operations tcp4_net_ops = {
	.init = tcp4_proc_init_net,
	.exit = tcp4_proc_exit_net,
};

int __init tcp4_proc_init(void)
{
	return register_pernet_subsys(&tcp4_net_ops);
}

void tcp4_proc_exit(void)
{
	unregister_pernet_subsys(&tcp4_net_ops);
}
#endif /* CONFIG_PROC_FS */

struct sk_buff **tcp4_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct iphdr *iph = skb_gro_network_header(skb);

	switch (skb->ip_summed) {
	case CHECKSUM_COMPLETE:
		if (!tcp_v4_check(skb_gro_len(skb), iph->saddr, iph->daddr,
				  skb->csum)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			break;
		}

		/* fall through */
	case CHECKSUM_NONE:
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	return tcp_gro_receive(head, skb);
}
EXPORT_SYMBOL(tcp4_gro_receive);

int tcp4_gro_complete(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);

	th->check = ~tcp_v4_check(skb->len - skb_transport_offset(skb),
				  iph->saddr, iph->daddr, 0);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

	return tcp_gro_complete(skb);
}
EXPORT_SYMBOL(tcp4_gro_complete);

//tcp层的发送封装函数为tcp_transmit_skb，该函数中封装了TCP首部(包括选项字段)，tcp层封装好后，走向ip层的接口ops为ipv4_specific
//TCP协议传输层操作集，这个和应用层创建套接字相关，个人我理解是属于套接口层。TCP连接建立以及数据发送的ops函数在ipv4_specific
struct proto tcp_prot = { //接收的时候由tcp_protocol里面的recv函数跳转到这里面             TCP的套接口层操作集在inetsw_array数组中的inet_stream_ops
	.name			= "TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.connect		= tcp_v4_connect,  
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= tcp_v4_init_sock,  //inet_create中执行
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.recvmsg		= tcp_recvmsg,
	.backlog_rcv		= tcp_v4_do_rcv,
	.hash			= inet_hash,  //inet_create中执行  //将该传输控制块socket添加到tcp_hashinfo的对应hash中
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem		= sysctl_tcp_wmem,
	.sysctl_rmem		= sysctl_tcp_rmem,
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct tcp_sock),  //inet_init中的rc = proto_register(&tcp_prot, 1);确定了缓存，在创建struct sock的时候的空间大小就是这个obj_size
	.slab_flags		= SLAB_DESTROY_BY_RCU,
	.twsk_prot		= &tcp_timewait_sock_ops,
	.rsk_prot		= &tcp_request_sock_ops,
	.h.hashinfo		= &tcp_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt	= compat_tcp_setsockopt,
	.compat_getsockopt	= compat_tcp_getsockopt,
#endif
};


static int __net_init tcp_sk_init(struct net *net)
{
	return inet_ctl_sock_create(&net->ipv4.tcp_sock,
				    PF_INET, SOCK_RAW, IPPROTO_TCP, net);
}

static void __net_exit tcp_sk_exit(struct net *net)
{
	inet_ctl_sock_destroy(net->ipv4.tcp_sock);
}

static void __net_exit tcp_sk_exit_batch(struct list_head *net_exit_list)
{
	inet_twsk_purge(&tcp_hashinfo, &tcp_death_row, AF_INET);
}

static struct pernet_operations __net_initdata tcp_sk_ops = {
       .init	   = tcp_sk_init,
       .exit	   = tcp_sk_exit,
       .exit_batch = tcp_sk_exit_batch,
};

void __init tcp_v4_init(void)
{
	inet_hashinfo_init(&tcp_hashinfo);
	if (register_pernet_subsys(&tcp_sk_ops))
		panic("Failed to create the TCP control socket.\n");
}

EXPORT_SYMBOL(ipv4_specific);
EXPORT_SYMBOL(tcp_hashinfo);
EXPORT_SYMBOL(tcp_prot);
EXPORT_SYMBOL(tcp_v4_conn_request);
EXPORT_SYMBOL(tcp_v4_connect);
EXPORT_SYMBOL(tcp_v4_do_rcv);
EXPORT_SYMBOL(tcp_v4_remember_stamp);
EXPORT_SYMBOL(tcp_v4_send_check);
EXPORT_SYMBOL(tcp_v4_syn_recv_sock);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(tcp_proc_register);
EXPORT_SYMBOL(tcp_proc_unregister);
#endif
EXPORT_SYMBOL(sysctl_tcp_low_latency);


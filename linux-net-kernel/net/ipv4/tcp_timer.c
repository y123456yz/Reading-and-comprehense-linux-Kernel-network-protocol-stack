/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <linux/gfp.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;
int sysctl_tcp_thin_linear_timeouts __read_mostly;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}

EXPORT_SYMBOL(tcp_init_xmit_timers);

//关闭套接字并释放资源
static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int shift = 0;

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		shift++;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		shift++;

	if (tcp_too_many_orphans(sk, shift)) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_tcp_mtu_probing) {
		if (!icsk->icsk_mtup.enabled) {
			icsk->icsk_mtup.enabled = 1;
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			int mss;

			mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1;
			mss = min(sysctl_tcp_base_mss, mss);
			mss = max(mss, 68 - tp->tcp_header_len);
			icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
}

/* This function calculates a "timeout" which is equivalent to the timeout of a
 * TCP connection after "boundary" unsuccessful, exponentially backed-off
 * retransmissions with an initial RTO of TCP_RTO_MIN or TCP_TIMEOUT_INIT if
 * syn_set flag is set.
 */
static bool retransmits_timed_out(struct sock *sk,
				  unsigned int boundary,
				  bool syn_set)
{
	unsigned int timeout, linear_backoff_thresh;
	unsigned int start_ts;
	unsigned int rto_base = syn_set ? TCP_TIMEOUT_INIT : TCP_RTO_MIN;

	if (!inet_csk(sk)->icsk_retransmits)
		return false;

	if (unlikely(!tcp_sk(sk)->retrans_stamp))
		start_ts = TCP_SKB_CB(tcp_write_queue_head(sk))->when;
	else
		start_ts = tcp_sk(sk)->retrans_stamp;

	linear_backoff_thresh = ilog2(TCP_RTO_MAX/rto_base);

	if (boundary <= linear_backoff_thresh)
		timeout = ((2 << boundary) - 1) * rto_base;
	else
		timeout = ((2 << linear_backoff_thresh) - 1) * rto_base +
			  (boundary - linear_backoff_thresh) * TCP_RTO_MAX;

	return (tcp_time_stamp - start_ts) >= timeout;
}

/* A write timeout has occurred. Process the after effects. */
/*
 * 当发生重传之后,需要检测当前的资源使用
 * 情况.如果重传达到上限则需要立即关闭套接字
 */

static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int retry_until;
	bool do_reset, syn_set = 0;

    /*
	 * 在建立连接阶段超时,则需要检测使用的
	 * 路由缓存项,并获取重试次数的最大值.
	 */
	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		if (icsk->icsk_retransmits)
			dst_negative_advice(sk);
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		syn_set = 1;
	} else {
	    /*
		 * 当重传次数达到sysctl_tcp_retries1时,则需要进行
		 * 黑洞检测.完成黑洞检测后还需检测使用的
		 * 路由缓存项.
		 * 系统启用路径MTU发现时,如果路径MTU发现的
		 * 控制数据块中的开关没有开启,则将其开启,
		 * 并根据PMTU同步MSS.否则,将当前路径MTU发现
		 * 区间左端点的一半作为新区间的左端点重新
		 * 设定路径MTU发现区间,并根据路径MTU同步MSS.
		 */
		if (retransmits_timed_out(sk, sysctl_tcp_retries1, 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			dst_negative_advice(sk);
		}

        /*
		 * 如果当前套接字连接已断开并即将关闭,则
		 * 需要对当前使用的资源进行检测.当前的孤
		 * 儿套接字数量达到sysctl_tcp_max_orphans或者当前
		 * 已使用内存达到硬性限制时,需要即刻关闭
		 * 该套接字,这虽然不符合TCP的规范,但为了防
		 * 止DoS攻击必须这么处理.
		 */
		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				   !retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

    /*
	 * 当重传次数达到建立连接重传上限、超时
	 * 重传上限或确认连接异常期间重试上限这
	 * 三种上限之一时，都必须关闭套接字，并
	 * 且需要报告相应的错误。
	 */
	if (retransmits_timed_out(sk, retry_until, syn_set)) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/*
 * 延时ACK"定时器在TCP收到必须被确认但无需马上发出
 * 确认的段时设定，TCP在200ms后发送确认响应。如果在
 * 这200ms内，有数据要在该连接上发送，延时ACK响应就
 * 可随数据一起发送回对端，称为捎带确认。
 */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	/*
	 * 如果传输控制块已被用户进程锁定，
	 * 则此时不能作处理，只是重新设置
	 * 定时器超时时间，同时设置blocked
	 * 标记。
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		icsk->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		sk_reset_timer(sk, &icsk->icsk_delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

    /*
	 * 回收缓存
	 */
	sk_mem_reclaim_partial(sk);

    /*
	 * 如果TCP状态为CLOSE，或者没有启动延时发送
	 * ACK定时器，则无需作进一步处理。
	 */
	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

    /*
	 * 如果超时时间还未到，则重新复位定时器，
	 * 然后退出。
	 */
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}

	/*
	 * 检测完成后，正式进入延迟确认处理之前，
	 * 需去掉ICSK_ACK_TIMER标志。
	 */
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER;

    /*
	 * 如果ucopy控制块中的prequeue队列不为空，则
	 * 通过sk_backlog_rcv接口处理sk_backlog_rcv队列中的
	 * SKB。TCP中sk_backlog_rcv接口为tcp_v4_do_rcv()，由这个函数添加到sk->sk_receive_queue队列中。
	 */
	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb);

		tp->ucopy.memory = 0;
	}

    /*
	 * 如果此时有ACK需要发送，则调用tcp_send_ack()构造
	 * 并发送ACK段，在发送ACK段之前需先离开pingpong
	 * 模式，并重新设定延时确认的估算值。
	 */
	if (inet_csk_ack_scheduled(sk)) {
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto);
		} else {
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.ato      = TCP_ATO_MIN;
		}
		tcp_send_ack(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 * "持续"定时器在对端通告接收窗口为0，阻止TCP继续发送
 * 数据时设定。由于连接对端发送的窗口通告不可靠(只有
 * 数据才会确认，ACK不会确认)，允许TCP继续发送数据的后
 * 续窗口更新有可能丢失，因此，如果TCP有数据发送，而
 * 对端通告接收窗口为0，则持续定时器启动，超时后向
 * 对端发送1字节的数据，以判断对端接收窗口是否已打开。
 * 与重传定时器类似，持续定时器的超时值也是动态计算的，
 * 取决于连接的往返时间，在5~60s之间取值。
 * tcp_probe_timer()为持续定时器超时的处理函数。探测定时器就是当接收到对端的window为0的时候，需要探测对端窗口是否变大，
 */ //真正的probe报文发送在tcp_send_probe0中的tcp_write_wakeup             探测定时器在tcp_ack函数中激活， 或者在__tcp_push_pending_frames中的tcp_check_probe_timer激活
static void tcp_probe_timer(struct sock *sk) ////tcp_write_timer包括数据报重传tcp_retransmit_timer和窗口探测定时器tcp_probe_timer
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !tcp_send_head(sk)) {
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;

    /*
	 * 处理连接已断开，套接字即将关闭的情况
	 */
	if (sock_flag(sk, SOCK_DEAD)) {
	    /*
		 * TCP协议规定RTT的最大值为120s(TCP_RTO_MAX)，因此
		 * 可以通过将指数退避算法得出的超时时间与
		 * RTT最大值相比，来判断是否需要给对方发送
		 * RST。
		 */
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);

        /*
		 * 如果连接已断开，套接字即将关闭，则获取在
		 * 关闭本端TCP连接前重试次数的上限。
		 */
		max_probes = tcp_orphan_retries(sk, alive);

        /*
		 * 释放资源，如果该套接字在释放过程中被关闭，
		 * 就无需再发送持续探测段了。
		 */
		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) {
		tcp_write_err(sk);
		/*
		 * 如果持续定时器或保活定时器周期性发送出但未被确认
		 * 的TCP段数目达到上限，则作出错处理，同时关闭TCP套接字。
		 */
	} else {
		/* Only send another probe if we didn't close things up. */
		/*
		 * 否则，再一次发送持续定时器。
		 */
		tcp_send_probe0(sk);
	}
}

/*
 *	The TCP retransmit timer.
 */
////tcp_write_timer包括数据报重传tcp_retransmit_timer和窗口探测定时器tcp_probe_timer
//见tcp_event_new_data_sent，prior_packets为0时才会重启定时器,而prior_packets则是发送未确认的段的个数,也就是说如果发送了很多段,如果前面的段没有确认,那么后面发送的时候不会重启这个定时器.
//tcp_rearm_rto ///为0说明所有的传输的段都已经acked。此时remove定时器。否则重启定时器。  
void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

    /*
	 * 如果此时从发送队列输出的段都已
	 * 得到了确认,则无需重传处理.
	 */
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_write_queue_empty(sk));

    /*
	 * 在重传过程中，如果超时重传超时上限TCP_RTO_MAX(120s)还没有接收
	 * 到对方的确认，则认为有错误发生，调用tcp_write_err()报告错误并
	 * 关闭套接字，然后返回；否则TCP进入拥塞控制的LOSS状态，并重新
	 * 传送重传队列中的第一个段。
	 */
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &inet->inet_daddr, ntohs(inet->inet_dport),
			       inet->inet_num, tp->snd_una, tp->snd_nxt);
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &np->daddr, ntohs(inet->inet_dport),
			       inet->inet_num, tp->snd_una, tp->snd_nxt);
		}
#endif
#endif
        /*
		 * 在重传过程中，如果超时重传超时上限TCP_RTO_MAX(120s)还没有接收
		 * 到对方的确认，则认为有错误发生，调用tcp_write_err()报告错误并
		 * 关闭套接字，然后返回；否则TCP进入拥塞控制的LOSS状态，并重新
		 * 传送重传队列中的第一个段。
		 */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk, 0);
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk));
		/*
		 * 由于发生了重传，传输控制块中的路由缓存项需更新，
		 * 因此将其清除，最后跳转到out_reset_timer标签处处理。
		 */
		__sk_dst_reset(sk);
		goto out_reset_timer;
	}

    //走到下面说明是处于连接建立阶段或者对方的滑动窗口为0了


    /*
	 * 当发生重传之后,需要检测当前的资源使用
	 * 情况和重传的次数.如果重传次数达到上限,
	 * 则需要报告错误并强行关闭套接字.如果只
	 * 是使用的资源达到使用的上限,则不进行此
	 * 次重传.
	 */
	if (tcp_write_timeout(sk))
		goto out;

    /*
	 * 如果重传次数为0,说明刚进入重传阶段,则
	 * 根据不同的拥塞状态进行相关的数据统计.   第一次重传可能是对方滑动窗口满，需要进行拥塞控制
	 */
	if (icsk->icsk_retransmits == 0) {
		int mib_idx;

		if (icsk->icsk_ca_state == TCP_CA_Disorder) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
	}


    /*
	 * 判断是否可使用F-RTO算法进行处理,
	 * 如果可以则调用tcp_enter_frto()进行F-RTO
	 * 算法的处理,否则调用tcp_enter_loss()进入
	 * 常规的RTO慢启动重传恢复阶段.
	 */
	if (tcp_use_frto(sk)) {
		tcp_enter_frto(sk);
	} else {
		tcp_enter_loss(sk, 0);
	}

    /*
	 * 如果发送重传队列上的第一个SKB失败,则复位
	 * 重传定时器,等待下次重传.
	 */
	if (tcp_retransmit_skb(sk, tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */

	/*
	 * 发送成功后,递增指数退避算法指数icsk_backoff
	 * 和累计重传次数icsk_retransmits.
	 */
	icsk->icsk_backoff++;
	icsk->icsk_retransmits++;

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);//计算rto，并重启定时器，这里使用karn算法，也就是下次超时时间增加一倍/  
	} else {
		/* Use normal (exponential) backoff */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}

	/*
	 * 完成重传后,需要设重传超时时间,然后复位重传
	 * 定时器,等待下次重传.
	 */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0))
		__sk_dst_reset(sk);

out:;
}

/*
 * 重传定时器在TCP发送数据时设定，如果定时器
 * 已超时而对端确认还未到达，则TCP将重传数据。
 * 重传定时器的超时时间值是动态计算的，取决于
 * TCP为该连接测量的往返时间以及该段已被重传
 * 的次数。
 */ //tcp_write_timer包括数据报重传tcp_retransmit_timer和窗口探测定时器tcp_probe_timer
static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

	bh_lock_sock(sk);
	/*
	 * 若传输控制块被用户进程锁定，则只能稍后再试，
	 * 因此重新设置定时器超时时间。
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}
        /*
         * TCP状态为CLOSE或未定义定时器事件，则
         * 无需作处理。
         */
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

    /*
	 * 如果还未到定时器超时时间，则无需
	 * 作处理，重新设置定时器的下次的超
	 * 时时间。
	 */
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

    /*
	 * 由于重传定时器和持续定时器功能是共用了
	 * 一个定时器实现的，因此需根据定时器事件
	 * 来区分激活的是哪种定时器；如果event为
	 * ICSK_TIME_RETRANS，则调用tcp_retransmit_timer()进行重传
	 * 处理；如果为ICSK_TIME_PROBE0，则调用tcp_probe_timer()
	 * 进行持续定时器的处理.
	 */
	event = icsk->icsk_pending;
	icsk->icsk_pending = 0;

	switch (event) {
	case ICSK_TIME_RETRANS:
		tcp_retransmit_timer(sk);
		break;
	case ICSK_TIME_PROBE0:
		tcp_probe_timer(sk);
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

/*
 * tcp_synack_timer()只是简单地调用inet_csk_reqsk_queue_prune()，
 * 用来扫描半连接散列表。然后再设定建立连接
 * 定时器，间隔时间为TCP_SYNQ_INTERVAL。
 */
static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_syn_ack_timeout(struct sock *sk, struct request_sock *req)
{
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPTIMEOUTS);
}
EXPORT_SYMBOL(tcp_syn_ack_timeout);

void tcp_set_keepalive(struct sock *sk, int val)
{
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val)
		inet_csk_delete_keepalive_timer(sk);
}

/*
 * tcp_keepalive_timer()实现了TCP中的三个定时器:连接建立定时器、
 * 保活定时器和FIN_WAIT_2定时器。这是由于这三个定时器分别
 * 处于LISTEN、ESTABLISHED和FIN_WAIT_2三种状态，因此不必区分它们，
 * 只需简单地通过当前的TCP状态就能判断当前执行的是何种
 * 定时器。
 * 
 * "保活"定时器在应用进程选取了套接字SO_KEEPALIVE选项时生效。
 * 如果连接的连续空闲时间超过2小时，则保活定时器超时，向
 * 对端发送连接探测段，强迫对端响应。
 * 1)如果能接收到预期的响应，则TCP可确定对端主机工作正常，
 *    在该连接再次空闲超过2小时之前，TCP不会再进行保活探测。
 * 2)如果收到的是其他响应，则TCP可能确定对端主机已重启。
 * 3)如果是连续若干次保活测试都未收到响应，则TCP假定对端
 *    主机已崩溃，尽管它无法区分是主机故障(例如系统崩溃而
 * 尚未重启)还是连接故障(例如中间的路由器发送故障或电话线
 * 断了)。
 * 
 * 
 * FIN_WAIT_1定时器:
 * 当某个连接从FIN_WAIT_1状态变迁到FIN_WAIT_2状态，且不能再接收
 * 任何新数据时，则意味着应用进程调用了close()而非shutdown()，
 * 没有利用TCP的半关闭功能，FIN_WAIT_2定时器启动，超时时间为
 * 10min，在定时器第一次超时后，重新设置超时时间为75s，第二次
 * 超时后关闭连接。加入这个定时器的目的是为了避免对端一直
 * 不发FIN，某个连接会永远滞留在FIN_WAIT_2状态。
 * FIN_WAIT_2定时器并不是全部由tcp_keepalive_timer()来实现，事实上，只有
 * 在处于FIN_WAIT_2状态的时间超过60s时，才会将该传输控制块放到
 * tcp_keepalive_timer()中处理，在sk_timer定时器中延时60s以后的部分，由
 * tcp_time_wait()继续处理。见tcp_rcv_state_process
 */

 //通过TCP的不同状态，来实现连接定时器、FIN_WAIT_2定时器以及TCP保活定时器
 ////??疑问:重传定时器和探测定时器为什么后面的定时器不会把前面sk_reset_timer的定时器给覆盖了呢，那前面的定时器不是不起作用吗?
    //因为在启用重传定时器的过程中，表示对端窗口是不为0的，在启动探测定时器的时候也会检查是否有未被确认的ack等。他们处于不同的阶段，所以他们是不可能同时存在的
    //这里的tcp_keepalive_timer定时器也是一样的
static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	/*
	 * 如果传输控制块被用户进程锁定，则重新设定
	 * 定时时间，0.05s后再次激活。
	 */
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

    /*
	 * 如果当前TCP状态为LISTEN，则说明执行的是连接
	 * 建立定时器，调用tcp_synack_timer()处理。
	 */
	if (sk->sk_state == TCP_LISTEN) { //说明是在建立TCP连接的过程中的定时器处理过程
		tcp_synack_timer(sk);
		goto out;
	}

    /*
	 * 处理FIN_WAIT_2状态定时器时，TCP状态必须为
	 * FIN_WAIT_2且套接字状态为DEAD。
	 */ //tcp_rcv_state_process中收到第一个FIN ack后会进入TCP_FIN_WAIT2状态
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) { //TCP关闭过程中的定时器处理过程，从tcp_rcv_state_process跳转过来
	    /*
		 * 停留在FIN_WAIT_2状态的时间大于或等于0的情况下，
		 * 如果FIN_WAIT_2定时器剩余时间大于0，则调用
		 * tcp_time_wait()继续处理；否则给对端发送RST后
		 * 关闭套接字。
		 */
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo); //在tcp_rcv_state_process中的WAIT1状态，用掉了tcp_fin_time-TCP_TIMEWAIT_LEN，所以多余的的时间这里处理
				goto out;
			}
		}
		tcp_send_active_reset(sk, GFP_ATOMIC);
		goto death;
	}

    //下面是TCP连接建立过程中的保活处理过程
    /*
	 * 如果未启用保活功能或TCP状态为CLOSE，则不作
	 * 处理返回。
	 */
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

    /*
	 * 如果有已输出未确认的段，或者发送队列中还
	 * 存在未发送的段，则无需作处理，只需重新设
	 * 定保活定时器的超时时间。
	 */
	elapsed = keepalive_time_when(tp);
	/* It is alive without keepalive 8) */
	if (tp->packets_out || tcp_send_head(sk))
		goto resched;


	elapsed = keepalive_time_elapsed(tp);

	if (elapsed >= keepalive_time_when(tp)) {
	    /*
		 * 如果持续空闲时间超过了允许时间，并且在未设置
		 * 保活探测次数时，已发送保活探测段数超过了系统
		 * 默认的允许数tcp_keepalive_probes；或者在已设置保活探测
		 * 段的次数时，已发送次数超过了保活探测次数，则
		 * 需要断开连接，给对方发送RST段，并报告相应错误，
		 * 关闭相应的传输控制块。
		 */
		if (icsk->icsk_probes_out >= keepalive_probes(tp)) {
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}

		/* 发送保活段，并计算下次激活保活定时器的时间。*/
		if (tcp_write_wakeup(sk) <= 0) {
			icsk->icsk_probes_out++;
			elapsed = keepalive_intvl_when(tp);
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL;
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	sk_mem_reclaim(sk);

resched:
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}


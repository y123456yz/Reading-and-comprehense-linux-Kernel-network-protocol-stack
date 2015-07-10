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

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/workqueue.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/xfrm.h>

int sysctl_tcp_syncookies __read_mostly = 1;
EXPORT_SYMBOL(sysctl_tcp_syncookies);

/*
 * 表示当进程太忙而不能接受新的连接时，是否主动
 * 向对方发送RST段。默认值是0(false)。该选项可能会影
 * 响使用，只有在确认进程真的不能完成连接请求时
 * 才该打开此选项。通常用于apache这类服务，这样可
 * 以很快让客户端终止连接，让服务程序有机会处理
 * 已有的连接
 */
int sysctl_tcp_abort_on_overflow __read_mostly;

struct inet_timewait_death_row tcp_death_row = {  //关闭套接字的时候出现TIME_WAIT的inet_timewait_sock的管理，系统当前TIME_WAIT状态的套接字
	.sysctl_max_tw_buckets = NR_FILE * 2,
	.period		= TCP_TIMEWAIT_LEN / INET_TWDR_TWKILL_SLOTS,
	.death_lock	= __SPIN_LOCK_UNLOCKED(tcp_death_row.death_lock),
	.hashinfo	= &tcp_hashinfo,
	.tw_timer	= TIMER_INITIALIZER(inet_twdr_hangman, 0,
					    (unsigned long)&tcp_death_row),
	.twkill_work	= __WORK_INITIALIZER(tcp_death_row.twkill_work,
					     inet_twdr_twkill_work),
/* Short-time timewait calendar */

	.twcal_hand	= -1,
	.twcal_timer	= TIMER_INITIALIZER(inet_twdr_twcal_tick, 0,
					    (unsigned long)&tcp_death_row),
};

EXPORT_SYMBOL_GPL(tcp_death_row);

static __inline__ int tcp_in_window(u32 seq, u32 end_seq, u32 s_win, u32 e_win)
{
	if (seq == s_win)
		return 1;
	if (after(end_seq, s_win) && before(seq, e_win))
		return 1;
	return (seq == e_win && seq == end_seq);
}

/*
 * * Main purpose of TIME-WAIT state is to close connection gracefully,
 *   when one of ends sits in LAST-ACK or CLOSING retransmitting FIN
 *   (and, probably, tail of data) and one or more our ACKs are lost.
 * * What is TIME-WAIT timeout? It is associated with maximal packet
 *   lifetime in the internet, which results in wrong conclusion, that
 *   it is set to catch "old duplicate segments" wandering out of their path.
 *   It is not quite correct. This timeout is calculated so that it exceeds
 *   maximal retransmission timeout enough to allow to lose one (or more)
 *   segments sent by peer and our ACKs. This time may be calculated from RTO.
 * * When TIME-WAIT socket receives RST, it means that another end
 *   finally closed and we are allowed to kill TIME-WAIT too.
 * * Second purpose of TIME-WAIT is catching old duplicate segments.
 *   Well, certainly it is pure paranoia, but if we load TIME-WAIT
 *   with this semantics, we MUST NOT kill TIME-WAIT state with RSTs.
 * * If we invented some more clever way to catch duplicates
 *   (f.e. based on PAWS), we could truncate TIME-WAIT to several RTOs.
 *
 * The algorithm below is based on FORMAL INTERPRETATION of RFCs.
 * When you compare it to RFCs, please, read section SEGMENT ARRIVES
 * from the very beginning.
 *
 * NOTE. With recycling (and later with fin-wait-2) TW bucket
 * is _not_ stateless. It means, that strictly speaking we must
 * spinlock it. I do not want! Well, probability of misbehaviour
 * is ridiculously low and, seems, we could use some mb() tricks
 * to avoid misread sequence numbers, states etc.  --ANK
 */
enum tcp_tw_status
tcp_timewait_state_process(struct inet_timewait_sock *tw, struct sk_buff *skb,
			   const struct tcphdr *th)
{
	struct tcp_options_received tmp_opt;
	u8 *hash_location;
	struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
	int paws_reject = 0;

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(*th) >> 2) && tcptw->tw_ts_recent_stamp) {
		tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

		if (tmp_opt.saw_tstamp) {
			tmp_opt.ts_recent	= tcptw->tw_ts_recent;
			tmp_opt.ts_recent_stamp	= tcptw->tw_ts_recent_stamp;
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	if (tw->tw_substate == TCP_FIN_WAIT2) {
		/* Just repeat all the checks of tcp_rcv_state_process() */

		/* Out of window, send ACK */
		if (paws_reject ||
		    !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
				   tcptw->tw_rcv_nxt,
				   tcptw->tw_rcv_nxt + tcptw->tw_rcv_wnd))
			return TCP_TW_ACK;

		if (th->rst)
			goto kill;

		if (th->syn && !before(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt))
			goto kill_with_rst;

		/* Dup ACK? */
		if (!th->ack ||
		    !after(TCP_SKB_CB(skb)->end_seq, tcptw->tw_rcv_nxt) ||
		    TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq) {
			inet_twsk_put(tw);
			return TCP_TW_SUCCESS;
		}

		/* New data or FIN. If new data arrive after half-duplex close,
		 * reset.
		 */
		if (!th->fin ||
		    TCP_SKB_CB(skb)->end_seq != tcptw->tw_rcv_nxt + 1) {
kill_with_rst:
			inet_twsk_deschedule(tw, &tcp_death_row);
			inet_twsk_put(tw);
			return TCP_TW_RST;
		}

		/* FIN arrived, enter true time-wait state. */
		tw->tw_substate	  = TCP_TIME_WAIT;
		tcptw->tw_rcv_nxt = TCP_SKB_CB(skb)->end_seq;
		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent_stamp = get_seconds();
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
		}

		/* I am shamed, but failed to make it more elegant.
		 * Yes, it is direct reference to IP, which is impossible
		 * to generalize to IPv6. Taking into account that IPv6
		 * do not understand recycling in any case, it not
		 * a big problem in practice. --ANK */
		if (tw->tw_family == AF_INET &&
		    tcp_death_row.sysctl_tw_recycle && tcptw->tw_ts_recent_stamp &&
		    tcp_v4_tw_remember_stamp(tw))
			inet_twsk_schedule(tw, &tcp_death_row, tw->tw_timeout,
					   TCP_TIMEWAIT_LEN);
		else
			inet_twsk_schedule(tw, &tcp_death_row, TCP_TIMEWAIT_LEN,
					   TCP_TIMEWAIT_LEN);
		return TCP_TW_ACK;
	}

	/*
	 *	Now real TIME-WAIT state.
	 *
	 *	RFC 1122:
	 *	"When a connection is [...] on TIME-WAIT state [...]
	 *	[a TCP] MAY accept a new SYN from the remote TCP to
	 *	reopen the connection directly, if it:
	 *
	 *	(1)  assigns its initial sequence number for the new
	 *	connection to be larger than the largest sequence
	 *	number it used on the previous connection incarnation,
	 *	and
	 *
	 *	(2)  returns to TIME-WAIT state if the SYN turns out
	 *	to be an old duplicate".
	 */

	if (!paws_reject &&
	    (TCP_SKB_CB(skb)->seq == tcptw->tw_rcv_nxt &&
	     (TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq || th->rst))) {
		/* In window segment, it may be only reset or bare ack. */

		if (th->rst) {
			/* This is TIME_WAIT assassination, in two flavors.
			 * Oh well... nobody has a sufficient solution to this
			 * protocol bug yet.
			 */
			if (sysctl_tcp_rfc1337 == 0) {
kill:
				inet_twsk_deschedule(tw, &tcp_death_row);
				inet_twsk_put(tw);
				return TCP_TW_SUCCESS;
			}
		}
		inet_twsk_schedule(tw, &tcp_death_row, TCP_TIMEWAIT_LEN,
				   TCP_TIMEWAIT_LEN);

		if (tmp_opt.saw_tstamp) {
			tcptw->tw_ts_recent	  = tmp_opt.rcv_tsval;
			tcptw->tw_ts_recent_stamp = get_seconds();
		}

		inet_twsk_put(tw);
		return TCP_TW_SUCCESS;
	}

	/* Out of window segment.

	   All the segments are ACKed immediately.

	   The only exception is new SYN. We accept it, if it is
	   not old duplicate and we are not in danger to be killed
	   by delayed old duplicates. RFC check is that it has
	   newer sequence number works at rates <40Mbit/sec.
	   However, if paws works, it is reliable AND even more,
	   we even may relax silly seq space cutoff.

	   RED-PEN: we violate main RFC requirement, if this SYN will appear
	   old duplicate (i.e. we receive RST in reply to SYN-ACK),
	   we must return socket to time-wait state. It is not good,
	   but not fatal yet.
	 */

	if (th->syn && !th->rst && !th->ack && !paws_reject &&
	    (after(TCP_SKB_CB(skb)->seq, tcptw->tw_rcv_nxt) ||
	     (tmp_opt.saw_tstamp &&
	      (s32)(tcptw->tw_ts_recent - tmp_opt.rcv_tsval) < 0))) {
		u32 isn = tcptw->tw_snd_nxt + 65535 + 2;
		if (isn == 0)
			isn++;
		TCP_SKB_CB(skb)->when = isn;
		return TCP_TW_SYN;
	}

	if (paws_reject)
		NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_PAWSESTABREJECTED);

	if (!th->rst) {
		/* In this case we must reset the TIMEWAIT timer.
		 *
		 * If it is ACKless SYN it may be both old duplicate
		 * and new good SYN with random sequence number <rcv_nxt.
		 * Do not reschedule in the last case.
		 */
		if (paws_reject || th->ack)
			inet_twsk_schedule(tw, &tcp_death_row, TCP_TIMEWAIT_LEN,
					   TCP_TIMEWAIT_LEN);

		/* Send ACK. Note, we do not put the bucket,
		 * it will be released by caller.
		 */
		return TCP_TW_ACK;
	}
	inet_twsk_put(tw);
	return TCP_TW_SUCCESS;
}

/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
 
/*
 * Move a socket to time-wait or dead fin-wait-2 state.
 */
/*
 * @sk: 被取代的传输控制块。
 * @state: timewait控制块内部的状态，为FIN_WAIT2或TIME_WAIT
 * @timeo: 等待超时时间  //本端发送的fin已经收到确认，等待对方发送fin,或者主动关闭端收到了第二个fin进入time_wait状态
 sock结构进入TIME_WAIT状态有两种情况：一种是在真正进入了TIME_WAIT状态，还有一种是真实的状态是FIN_WAIT_2的TIME_WAIT状态。之所以让FIN_WAIT_2状态在没有
 接收到FIN包的情况下也可以进入TIME_WAIT状态是因为tcp_sock结构占用的资源要比tcp_timewait_sock结构占用的资源多，而且在TIME_WAIT下也可以处理连接的关闭。
 内核在处理时通过inet_timewait_sock结构的tw_substate成员来区分这种两种情况。
 */
 //参考:http://blog.csdn.net/justlinux2010/article/details/9070057
void tcp_time_wait(struct sock *sk, int state, int timeo)
{
	struct inet_timewait_sock *tw = NULL;
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	int recycle_ok = 0;

	/*
	 * 如果启用tw_recycle，且ts_recent_stamp有效，则记录
	 * 相关时间戳信息到对端信息管理块中
	   tcp_timestamps参数用来设置是否启用时间戳选项，tcp_tw_recycle参数用来启用快速回收TIME_WAIT套接字。tcp_timestamps参数会影响到
	   tcp_tw_recycle参数的效果。如果没有时间戳选项的话，tcp_tw_recycle参数无效，
	 */
	if (tcp_death_row.sysctl_tw_recycle && tp->rx_opt.ts_recent_stamp)
		/*
		 * 调用的是tcp_v4_remember_stamp()。
		  如果没有时间戳选项，tp->rx_opt.ts_recent_stamp的值为0，这样局部变量recycle_ok的值为0，在后面就会使用默认的时间TCP_TIMEWAIT_LEN（60s）
		 作为TIME_WAIT状态的时间长度
		  允许重用timewait传输控制块，并且成功记录了时间戳,则recycle_ok为1

		  tcp_timestamps参数用来设置是否启用时间戳选项，tcp_tw_recycle参数用来启用快速回收TIME_WAIT套接字。tcp_timestamps参数会影响到tcp_tw_recycle参数的效果。如果没有时间戳选项的话，tcp_tw_recycle参数无效
		 */
		recycle_ok = icsk->icsk_af_ops->remember_stamp(sk);

	/*
	 * 如果当前系统中TIME_WATI状态的套接字数未
	 * 达到最大值，则允许分配timewait控制块。
	 * inet_twsk_alloc()用来分配timewait控制块，并根据
	 * 传输控制块设置其对应的属性和内部状态
	 */
	if (tcp_death_row.tw_count < tcp_death_row.sysctl_max_tw_buckets)
		tw = inet_twsk_alloc(sk, state);

	/*
	 * 如果timewait控制块分配成功，则做相应设置，
	 * 同时进入TIME_WAIT状态
	 */
	if (tw != NULL) { //所以在TIME_WAIT套接字数量超过系统限制或者内存不足
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		/*
		 * 根据超时重传时间计算TIME_WAIT状态的
		 * 超时时间，后者是前者的3.5倍。
		 * 为什么是3.5倍参见inet_twsk_schedule()函数

		 下面在来看看为什么rto的值要选择为icsk->icsk_rto的3.5倍，也就是RTO*3.5，而不是2倍、4倍呢？我们知道，在FIN_WAIT_2状态下接收到FIN包后，会给对
		 端发送ACK包，完成TCP连接的关闭。但是最后的这个ACK包可能对端没有收到，在过了RTO（超时重传时间）时间后，对端会重新发送FIN包，这时需要再次给对
		 端发送ACK包，所以TIME_WAIT状态的持续时间要保证对端可以重传两次FIN包。如果重传两次的话，TIME_WAIT的时间应该为RTO*（0.5+0.5+0.5）=RTO*1.5，但是
		 这里却是RTO*3.5。这是因为在重传情况下，重传超时时间采用一种称为“指数退避”的方式计算。例如：当重传超时时间为1S的情况下发生了数据重传，我们就用
		 重传超时时间为2S的定时器来重传数据，下一次用4S，一直增加到64S为止（参见tcp_retransmit_timer（））。所以这里的RTO*3.5=RTO*0.5+RTO*1+RTO*2,其中
		 RTO*0.5是第一次发送ACK的时间到对端的超时时间（系数就是乘以RTO的值），RTO*1是对端第一次重传FIN包到ACK包到达对端的超时时间，RTO*2是对端第二次重传
		 FIN包到ACK包到达对端的超时时间。注意，重传超时时间的指数退避操作（就是乘以2）是在重传之后执行的，所以第一次重传的超时时间和第一次发送的超时时间
		 相同。整个过程及时间分布如下图所示（注意：箭头虽然指向对端，只是用于描述过程，数据包并未被接收到）：参考:http://blog.csdn.net/justlinux2010/article/details/9070057
		 */
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);//icsk->icsk_rto的值是超时重传的时间，这个值是根据网络情况动态计算的

		/*
		 * 从TCP控制块中获取对应的属性值
		 * 设置到timewait控制块中
		 */
		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			struct inet6_timewait_sock *tw6;

			tw->tw_ipv6_offset = inet6_tw_offset(sk->sk_prot);
			tw6 = inet6_twsk((struct sock *)tw);
			ipv6_addr_copy(&tw6->tw_v6_daddr, &np->daddr);
			ipv6_addr_copy(&tw6->tw_v6_rcv_saddr, &np->rcv_saddr);
			tw->tw_ipv6only = np->ipv6only;
		}
#endif

#ifdef CONFIG_TCP_MD5SIG
		/*
		 * The timewait bucket does not have the key DB from the
		 * sock structure. We just make a quick copy of the
		 * md5 key being used (if indeed we are using one)
		 * so the timewait ack generating code has the key.
		 */
		do {
			struct tcp_md5sig_key *key;
			memset(tcptw->tw_md5_key, 0, sizeof(tcptw->tw_md5_key));
			tcptw->tw_md5_keylen = 0;
			key = tp->af_specific->md5_lookup(sk, sk);
			if (key != NULL) {
				memcpy(&tcptw->tw_md5_key, key->key, key->keylen);
				tcptw->tw_md5_keylen = key->keylen;
				if (tcp_alloc_md5sig_pool(sk) == NULL)
					BUG();
			}
		} while (0);
#endif

		/* Linkage updates. */
		/*
		 * 将timewait控制块添加到tcp_hashinfo的ebash散列表中，
		 * 将被替代的TCP控制块从ehash散列表中删除。这样
		 * FIN_WAIT2和TIME_WAIT状态下也可以进行输入的处理。
		 * 同时将该timewait控制块添加到bhash散列表中，但
		 * 并不删除该散列表中被替代的TCP控制块，因为
		 * 只要inet->num不为0，这个绑定关系就存在，
		 * 即使该套接字已经关闭
		 */
		__inet_twsk_hashdance(tw, sk, &tcp_hashinfo);

		/* Get the TIME_WAIT timeout firing. */
		/*
		 * TIME_WAIT的超时时间不得小于3.5倍的超时
		 * 重传的时间
		 */
		if (timeo < rto)
			timeo = rto;

        /*
         * 允许重用timewait传输控制块，并且成功记录了时间戳,
         * 则recycle_ok为1，此时会使用rto来设置真正的TIME-WAIT
         * 状态的时间(参见tcp_timewait_state_process())，
         * 否则使用固定的TCP_TIMEWAIT_LEN来设置TIME-WAIT状态的
         * 时间。
          如果没有时间戳选项，tp->rx_opt.ts_recent_stamp的值为0，这样局部变量recycle_ok的值为0，在后面就会使用默认的时间TCP_TIMEWAIT_LEN（60s）
		 作为TIME_WAIT状态的时间长度
         */
		if (recycle_ok) {//在设置tcp_tw_recycle参数的情况下，tw->tw_timeout的值为rto，否则为TCP_TIMEWAIT_LEN。所以tcp_tw_recycle参数如果要实现对回收TIME_WAIT状态套接字的加速，需要这个时间rto小于TCP_TIMEWAIT_LEN。rto的值由下面的式子计算：
			tw->tw_timeout = rto;
		} else {
			tw->tw_timeout = TCP_TIMEWAIT_LEN;
			if (state == TCP_TIME_WAIT)
				timeo = TCP_TIMEWAIT_LEN;
		}

		/*
		 * 进入TIME_WAIT状态，并启动TIME_WAIT定时器,超时时间
         * 为timeo,但是上限为TCP_TIMEWAIT_LEN，即超时时间最多
         * 不能超过TCP_TIMEWAIT_LEN。
		 */
		inet_twsk_schedule(tw, &tcp_death_row, timeo,
				   TCP_TIMEWAIT_LEN);
		inet_twsk_put(tw); 
		//这里后会在后面释放原来的struct sock
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		LIMIT_NETDEBUG(KERN_INFO "TCP: time wait bucket table overflow\n");
	}

	/*
	 * 将TCP中的一些测量值更新到它路由缓存项的
	 * 度量值中，然后关闭并释放传输控制块
	 */
	tcp_update_metrics(sk);
	tcp_done(sk);
}
void tcp_time_wait1(struct sock *sk, int state, int timeo)
{
	struct inet_timewait_sock *tw = NULL;
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	int recycle_ok = 0;

	if (tcp_death_row.sysctl_tw_recycle && tp->rx_opt.ts_recent_stamp)
		recycle_ok = icsk->icsk_af_ops->remember_stamp(sk);

	if (tcp_death_row.tw_count < tcp_death_row.sysctl_max_tw_buckets)
		tw = inet_twsk_alloc(sk, state);

	if (tw != NULL) {
		struct tcp_timewait_sock *tcptw = tcp_twsk((struct sock *)tw);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);

		tw->tw_rcv_wscale	= tp->rx_opt.rcv_wscale;
		tcptw->tw_rcv_nxt	= tp->rcv_nxt;
		tcptw->tw_snd_nxt	= tp->snd_nxt;
		tcptw->tw_rcv_wnd	= tcp_receive_window(tp);
		tcptw->tw_ts_recent	= tp->rx_opt.ts_recent;
		tcptw->tw_ts_recent_stamp = tp->rx_opt.ts_recent_stamp;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (tw->tw_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			struct inet6_timewait_sock *tw6;

			tw->tw_ipv6_offset = inet6_tw_offset(sk->sk_prot);
			tw6 = inet6_twsk((struct sock *)tw);
			ipv6_addr_copy(&tw6->tw_v6_daddr, &np->daddr);
			ipv6_addr_copy(&tw6->tw_v6_rcv_saddr, &np->rcv_saddr);
			tw->tw_ipv6only = np->ipv6only;
		}
#endif

#ifdef CONFIG_TCP_MD5SIG
		/*
		 * The timewait bucket does not have the key DB from the
		 * sock structure. We just make a quick copy of the
		 * md5 key being used (if indeed we are using one)
		 * so the timewait ack generating code has the key.
		 */
		do {
			struct tcp_md5sig_key *key;
			memset(tcptw->tw_md5_key, 0, sizeof(tcptw->tw_md5_key));
			tcptw->tw_md5_keylen = 0;
			key = tp->af_specific->md5_lookup(sk, sk);
			if (key != NULL) {
				memcpy(&tcptw->tw_md5_key, key->key, key->keylen);
				tcptw->tw_md5_keylen = key->keylen;
				if (tcp_alloc_md5sig_pool(sk) == NULL)
					BUG();
			}
		} while (0);
#endif

		/* Linkage updates. */
		__inet_twsk_hashdance(tw, sk, &tcp_hashinfo);

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (recycle_ok) {
			tw->tw_timeout = rto;
		} else {
			tw->tw_timeout = TCP_TIMEWAIT_LEN;
			if (state == TCP_TIME_WAIT)
				timeo = TCP_TIMEWAIT_LEN;
		}

		inet_twsk_schedule(tw, &tcp_death_row, timeo,
				   TCP_TIMEWAIT_LEN);
		inet_twsk_put(tw);
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		LIMIT_NETDEBUG(KERN_INFO "TCP: time wait bucket table overflow\n");
	}

	tcp_update_metrics(sk);
	tcp_done(sk);
}

void tcp_twsk_destructor(struct sock *sk)
{
#ifdef CONFIG_TCP_MD5SIG
	struct tcp_timewait_sock *twsk = tcp_twsk(sk);
	if (twsk->tw_md5_keylen)
		tcp_free_md5sig_pool();
#endif
}

EXPORT_SYMBOL_GPL(tcp_twsk_destructor);

static inline void TCP_ECN_openreq_child(struct tcp_sock *tp,
					 struct request_sock *req)
{
	tp->ecn_flags = inet_rsk(req)->ecn_ok ? TCP_ECN_OK : 0;
}

/* This is not only more efficient than what we used to do, it eliminates
 * a lot of code duplication between IPv4/IPv6 SYN recv processing. -DaveM
 *
 * Actually, we could lots of memory writes here. tp of listening
 * socket contains all necessary default parameters.
 */ //在inet_csk_reqsk_queue_add讲req和sk关联起来
struct sock *tcp_create_openreq_child(struct sock *sk, struct request_sock *req, struct sk_buff *skb)
{
	struct sock *newsk = inet_csk_clone(sk, req, GFP_ATOMIC);

	if (newsk != NULL) {
		const struct inet_request_sock *ireq = inet_rsk(req);
		struct tcp_request_sock *treq = tcp_rsk(req);
		struct inet_connection_sock *newicsk = inet_csk(newsk);
		struct tcp_sock *newtp = tcp_sk(newsk);
		struct tcp_sock *oldtp = tcp_sk(sk);
		struct tcp_cookie_values *oldcvp = oldtp->cookie_values;

		/* TCP Cookie Transactions require space for the cookie pair,
		 * as it differs for each connection.  There is no need to
		 * copy any s_data_payload stored at the original socket.
		 * Failure will prevent resuming the connection.
		 *
		 * Presumed copied, in order of appearance:
		 *	cookie_in_always, cookie_out_never
		 */
		if (oldcvp != NULL) {
			struct tcp_cookie_values *newcvp =
				kzalloc(sizeof(*newtp->cookie_values),
					GFP_ATOMIC);

			if (newcvp != NULL) {
				kref_init(&newcvp->kref);
				newcvp->cookie_desired =
						oldcvp->cookie_desired;
				newtp->cookie_values = newcvp;
			} else {
				/* Not Yet Implemented */
				newtp->cookie_values = NULL;
			}
		}

		/* Now setup tcp_sock */
		newtp->pred_flags = 0;

		newtp->rcv_wup = newtp->copied_seq =
		newtp->rcv_nxt = treq->rcv_isn + 1;

		newtp->snd_sml = newtp->snd_una =
		newtp->snd_nxt = newtp->snd_up =
			treq->snt_isn + 1 + tcp_s_data_size(oldtp);

		tcp_prequeue_init(newtp);

		tcp_init_wl(newtp, treq->rcv_isn);

		newtp->srtt = 0;
		newtp->mdev = TCP_TIMEOUT_INIT;
		newicsk->icsk_rto = TCP_TIMEOUT_INIT;

		newtp->packets_out = 0;
		newtp->retrans_out = 0;
		newtp->sacked_out = 0;
		newtp->fackets_out = 0;
		newtp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		/* So many TCP implementations out there (incorrectly) count the
		 * initial SYN frame in their delayed-ACK and congestion control
		 * algorithms that we must have the following bandaid to talk
		 * efficiently to them.  -DaveM
		 */
		newtp->snd_cwnd = 2;
		newtp->snd_cwnd_cnt = 0;
		newtp->bytes_acked = 0;

		newtp->frto_counter = 0;
		newtp->frto_highmark = 0;

		newicsk->icsk_ca_ops = &tcp_init_congestion_ops;

		tcp_set_ca_state(newsk, TCP_CA_Open);
		tcp_init_xmit_timers(newsk);
		skb_queue_head_init(&newtp->out_of_order_queue);
		newtp->write_seq = newtp->pushed_seq =
			treq->snt_isn + 1 + tcp_s_data_size(oldtp);

		newtp->rx_opt.saw_tstamp = 0;

		newtp->rx_opt.dsack = 0;
		newtp->rx_opt.num_sacks = 0;

		newtp->urg_data = 0;

		if (sock_flag(newsk, SOCK_KEEPOPEN))
			inet_csk_reset_keepalive_timer(newsk,
						       keepalive_time_when(newtp));

		newtp->rx_opt.tstamp_ok = ireq->tstamp_ok;
		if ((newtp->rx_opt.sack_ok = ireq->sack_ok) != 0) {
			if (sysctl_tcp_fack)
				tcp_enable_fack(newtp);
		}
		newtp->window_clamp = req->window_clamp;
		newtp->rcv_ssthresh = req->rcv_wnd;
		newtp->rcv_wnd = req->rcv_wnd;
		newtp->rx_opt.wscale_ok = ireq->wscale_ok;
		if (newtp->rx_opt.wscale_ok) {
			newtp->rx_opt.snd_wscale = ireq->snd_wscale;
			newtp->rx_opt.rcv_wscale = ireq->rcv_wscale;
		} else {
			newtp->rx_opt.snd_wscale = newtp->rx_opt.rcv_wscale = 0;
			newtp->window_clamp = min(newtp->window_clamp, 65535U);
		}
		newtp->snd_wnd = (ntohs(tcp_hdr(skb)->window) <<
				  newtp->rx_opt.snd_wscale);
		newtp->max_window = newtp->snd_wnd;

		if (newtp->rx_opt.tstamp_ok) {
			newtp->rx_opt.ts_recent = req->ts_recent;
			newtp->rx_opt.ts_recent_stamp = get_seconds();
			newtp->tcp_header_len = sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED;
		} else {
			newtp->rx_opt.ts_recent_stamp = 0;
			newtp->tcp_header_len = sizeof(struct tcphdr);
		}
#ifdef CONFIG_TCP_MD5SIG
		newtp->md5sig_info = NULL;	/*XXX*/
		if (newtp->af_specific->md5_lookup(sk, newsk))
			newtp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif
		if (skb->len >= TCP_MSS_DEFAULT + newtp->tcp_header_len)
			newicsk->icsk_ack.last_seg_size = skb->len - newtp->tcp_header_len;
		newtp->rx_opt.mss_clamp = req->mss;
		TCP_ECN_openreq_child(newtp, req);

		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_PASSIVEOPENS);
	}
	return newsk;
}

/*
 *	Process an incoming packet for SYN_RECV sockets represented
 *	as a request_sock.
 */
/*
 * 用来处理接收到的TCP段，处理过程如下:
 * 1. 解析并获取段中的TCP选项
 * 2. 检验TCP序号
 * 3. 如果是SYN段，则作为SYN段再处理一次
 * 4. 检测ACK段确认序号是否有效，无效则立即返回不作处理
 * 5. 检测ACK段序号是否有效，无效则丢弃该段
 * 6. 如果是RST段或者是新的SYN段，则向客户端返送RST段进行复位
 * 7. 校验通过，创建相应的"子"传输控制块
 * 8. 将连接请求块插入已完成连接的队列中，等待用户进程的accept()调用
 * 
 * @sk: 处理服务端连接过程的监听传输控制块
 * @skb: 接收到的TCP段
 * @req: 客户端请求的连接建立的连接请求块
 */
//这里面如果判断是ack会创建新的'子'struct sock，在函数tcp_v4_syn_recv_sock
//走到这里面来只可能是服务器端收到客户端的重传SYN或者 握手中的第三步ACK
struct sock *tcp_check_req(struct sock *sk, struct sk_buff *skb,
			   struct request_sock *req,
			   struct request_sock **prev)
{
	struct tcp_options_received tmp_opt;
	u8 *hash_location;
	struct sock *child;
	const struct tcphdr *th = tcp_hdr(skb);
	__be32 flg = tcp_flag_word(th) & (TCP_FLAG_RST|TCP_FLAG_SYN|TCP_FLAG_ACK);
	int paws_reject = 0;

	tmp_opt.saw_tstamp = 0;
	if (th->doff > (sizeof(struct tcphdr)>>2)) {
		tcp_parse_options(skb, &tmp_opt, &hash_location, 0);

		if (tmp_opt.saw_tstamp) {
			tmp_opt.ts_recent = req->ts_recent;
			/* We do not store true stamp, but it is not required,
			 * it can be estimated (approximately)
			 * from another data.
			 */
			tmp_opt.ts_recent_stamp = get_seconds() - ((TCP_TIMEOUT_INIT/HZ)<<req->retrans);
			paws_reject = tcp_paws_reject(&tmp_opt, th->rst);
		}
	}

	/* Check for pure retransmitted SYN. */
	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
	    flg == TCP_FLAG_SYN &&
	    !paws_reject) {
		/*
		 * RFC793 draws (Incorrectly! It was fixed in RFC1122)
		 * this case on figure 6 and figure 8, but formal
		 * protocol description says NOTHING.
		 * To be more exact, it says that we should send ACK,
		 * because this segment (at least, if it has no data)
		 * is out of window.
		 *
		 *  CONCLUSION: RFC793 (even with RFC1122) DOES NOT
		 *  describe SYN-RECV state. All the description
		 *  is wrong, we cannot believe to it and should
		 *  rely only on common sense and implementation
		 *  experience.
		 *
		 * Enforce "SYN-ACK" according to figure 8, figure 6
		 * of RFC793, fixed by RFC1122.
		 */
		req->rsk_ops->rtx_syn_ack(sk, req, NULL);
		return NULL;
	}

	/* Further reproduces section "SEGMENT ARRIVES"
	   for state SYN-RECEIVED of RFC793.
	   It is broken, however, it does not work only
	   when SYNs are crossed.

	   You would think that SYN crossing is impossible here, since
	   we should have a SYN_SENT socket (from connect()) on our end,
	   but this is not true if the crossed SYNs were sent to both
	   ends by a malicious third party.  We must defend against this,
	   and to do that we first verify the ACK (as per RFC793, page
	   36) and reset if it is invalid.  Is this a true full defense?
	   To convince ourselves, let us consider a way in which the ACK
	   test can still pass in this 'malicious crossed SYNs' case.
	   Malicious sender sends identical SYNs (and thus identical sequence
	   numbers) to both A and B:

		A: gets SYN, seq=7
		B: gets SYN, seq=7

	   By our good fortune, both A and B select the same initial
	   send sequence number of seven :-)

		A: sends SYN|ACK, seq=7, ack_seq=8
		B: sends SYN|ACK, seq=7, ack_seq=8

	   So we are now A eating this SYN|ACK, ACK test passes.  So
	   does sequence test, SYN is truncated, and thus we consider
	   it a bare ACK.

	   If icsk->icsk_accept_queue.rskq_defer_accept, we silently drop this
	   bare ACK.  Otherwise, we create an established connection.  Both
	   ends (listening sockets) accept the new incoming connection and try
	   to talk to each other. 8-)

	   Note: This case is both harmless, and rare.  Possibility is about the
	   same as us discovering intelligent life on another plant tomorrow.

	   But generally, we should (RFC lies!) to accept ACK
	   from SYNACK both here and in tcp_rcv_state_process().
	   tcp_rcv_state_process() does not, hence, we do not too.

	   Note that the case is absolutely generic:
	   we cannot optimize anything here without
	   violating protocol. All the checks must be made
	   before attempt to create socket.
	 */

	/* RFC793 page 36: "If the connection is in any non-synchronized state ...
	 *                  and the incoming segment acknowledges something not yet
	 *                  sent (the segment carries an unacceptable ACK) ...
	 *                  a reset is sent."
	 *
	 * Invalid ACK: reset will be sent by listening socket
	 */
	if ((flg & TCP_FLAG_ACK) &&
	    (TCP_SKB_CB(skb)->ack_seq !=
	     tcp_rsk(req)->snt_isn + 1 + tcp_s_data_size(tcp_sk(sk))))
		return sk;

	/* Also, it would be not so bad idea to check rcv_tsecr, which
	 * is essentially ACK extension and too early or too late values
	 * should cause reset in unsynchronized states.
	 */

	/* RFC793: "first check sequence number". */

	if (paws_reject || !tcp_in_window(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq,
					  tcp_rsk(req)->rcv_isn + 1, tcp_rsk(req)->rcv_isn + 1 + req->rcv_wnd)) {
		/* Out of window: send ACK and drop. */
		if (!(flg & TCP_FLAG_RST))
			req->rsk_ops->send_ack(sk, skb, req);
		if (paws_reject)
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_PAWSESTABREJECTED);
		return NULL;
	}

	/* In sequence, PAWS is OK. */

	if (tmp_opt.saw_tstamp && !after(TCP_SKB_CB(skb)->seq, tcp_rsk(req)->rcv_isn + 1))
		req->ts_recent = tmp_opt.rcv_tsval;

	if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn) {
		/* Truncate SYN, it is out of window starting
		   at tcp_rsk(req)->rcv_isn + 1. */
		flg &= ~TCP_FLAG_SYN;
	}

	/* RFC793: "second check the RST bit" and
	 *	   "fourth, check the SYN bit"
	 */
	if (flg & (TCP_FLAG_RST|TCP_FLAG_SYN)) {
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);
		goto embryonic_reset;
	}

	/* ACK sequence verified above, just make sure ACK is
	 * set.  If ACK not set, just silently drop the packet.
	 */
	if (!(flg & TCP_FLAG_ACK))
		return NULL;

	/* While TCP_DEFER_ACCEPT is active, drop bare ACK. */
	if (req->retrans < inet_csk(sk)->icsk_accept_queue.rskq_defer_accept &&
	    TCP_SKB_CB(skb)->end_seq == tcp_rsk(req)->rcv_isn + 1) {
		inet_rsk(req)->acked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPDEFERACCEPTDROP);
		return NULL;
	}

	/* OK, ACK is valid, create big socket and
	 * feed this segment to it. It will repeat all
	 * the tests. THIS SEGMENT MUST MOVE SOCKET TO
	 * ESTABLISHED STATE. If it will be dropped after
	 * socket is created, wait for troubles.
	 *//*
	 * 到此为止作为第三次握手的
	 * ACK段是有效的，因此调用tcp_v4_syn_recv_sock()
	 * 创建相应的"子"传输控制块
	 */
	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL);
	if (child == NULL)
		goto listen_overflow;

	inet_csk_reqsk_queue_unlink(sk, req, prev);
	inet_csk_reqsk_queue_removed(sk, req);

	inet_csk_reqsk_queue_add(sk, req, child);
	return child;

listen_overflow:
	if (!sysctl_tcp_abort_on_overflow) {
		inet_rsk(req)->acked = 1;
		return NULL;
	}

embryonic_reset:
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_EMBRYONICRSTS);
	if (!(flg & TCP_FLAG_RST))
		req->rsk_ops->send_reset(sk, skb);

	inet_csk_reqsk_queue_drop(sk, req, prev);
	return NULL;
}

/*
 * Queue segment on the new socket if the new socket is active,
 * otherwise we just shortcircuit this and continue with
 * the new socket.
 */

int tcp_child_process(struct sock *parent, struct sock *child,
		      struct sk_buff *skb)
{
	int ret = 0;
	int state = child->sk_state;

	if (!sock_owned_by_user(child)) {
		ret = tcp_rcv_state_process(child, skb, tcp_hdr(skb),
					    skb->len);
		/* Wakeup parent, send SIGIO */
		if (state == TCP_SYN_RECV && child->sk_state != state)
			parent->sk_data_ready(parent, 0);
	} else {
		/* Alas, it is possible again, because we do lookup
		 * in main socket hash table and lock on listening
		 * socket does not protect us more.
		 */
		__sk_add_backlog(child, skb);
	}

	bh_unlock_sock(child);
	sock_put(child);
	return ret;
}

EXPORT_SYMBOL(tcp_check_req);
EXPORT_SYMBOL(tcp_child_process);
EXPORT_SYMBOL(tcp_create_openreq_child);
EXPORT_SYMBOL(tcp_timewait_state_process);

/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path
 *					for decreased register pressure on x86
 *					and more readibility.
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

int sysctl_ip_default_ttl __read_mostly = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

//当IP头部封装好后，调用__ip_local_out
int __ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT, skb, NULL,
		       skb_dst(skb)->dev, dst_output);//通过dst_output最终会走到IP层输出函数dev_queue_xmit
}

//通过ip_local_out最终会走到IP层输出函数dev_queue_xmit
int ip_local_out(struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}
EXPORT_SYMBOL_GPL(ip_local_out);

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	skb_reset_mac_header(newskb);
	__skb_pull(newskb, skb_network_offset(newskb));
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	WARN_ON(!skb_dst(newskb));
	netif_rx_ni(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_sock *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/*
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  __be32 saddr, __be32 daddr, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct rtable *rt = skb_rtable(skb);
	struct iphdr *iph;

	/* Build the IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	ip_select_ident(iph, &rt->u.dst, sk);

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	/* Send it out. */
	return ip_local_out(skb);
}

EXPORT_SYMBOL_GPL(ip_build_and_send_pkt);

/*
 * 此函数通过邻居子系统将数据包输出
 * 到网络设备。
 */
static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = dst->dev;
	unsigned int hh_len = LL_RESERVED_SPACE(dev);

	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTMCAST, skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUTBCAST, skb->len);

	/* Be paranoid, rather than too clever. */
	/*
	 * 检测skb的前部空间是否还能存储链路层首部。
	 * 如果不够，则重新分配更大存储区的skb，
	 * 并释放原skb。
	 */
	if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	/*
	 * 如果缓存了链路层的首部，则调用
	 * neigh_hh_output()输出数据包。否则，
	 * 若存在对应的邻居项，则通过
	 * 邻居项的输出方法输出数据包。
	 */ //最后调用二层函数dev_queue_xmit
	if (dst->hh)
		return neigh_hh_output(dst->hh, skb);
	else if (dst->neighbour)
		return dst->neighbour->output(skb);

	/*
	 * 如果既没有缓存链路层的首部，又
	 * 不存在对应的邻居项，在这种情况
	 * 下，不能输出，释放该数据包。
	 */
	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

static inline int ip_skb_dst_mtu(struct sk_buff *skb)
{
	struct inet_sock *inet = skb->sk ? inet_sk(skb->sk) : NULL;

	return (inet && inet->pmtudisc == IP_PMTUDISC_PROBE) ?
	       skb_dst(skb)->dev->mtu : dst_mtu(skb_dst(skb));
}

static int ip_finish_output(struct sk_buff *skb)
{
#if defined(CONFIG_NETFILTER) && defined(CONFIG_XFRM)
	/* Policy lookup after SNAT yielded a new policy */
	if (skb_dst(skb)->xfrm != NULL) {
		IPCB(skb)->flags |= IPSKB_REROUTED;
		return dst_output(skb);
	}
#endif/*
	 /* 如果数据包长度大于MTU，则调用ip_fragment()
	 * 对IP数据包进行分片。
	 */
	if (skb->len > ip_skb_dst_mtu(skb) && !skb_is_gso(skb)) //如果不支持TSO或者GSO，tcp发送的时候是按照mss来组织skb的，所以skb->len会等于mtu  所以TCP叫分段，和IP分片不一样，只有UDP才有IP分片
		return ip_fragment(skb, ip_finish_output2);//SKB不是gso类型，并且skb->len大于mtu则需要分片   对方接受后的分片重组在netfilter中的ipv4_conntrack_defrag
	else
		return ip_finish_output2(skb);//如果报文长度小于mtu，或者skb是gso的，则走这里
}

int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = skb_rtable(skb);
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if (sk_mc_loop(sk)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    &&
		    ((rt->rt_flags & RTCF_LOCAL) ||
		     !(IPCB(skb)->flags & IPSKB_FORWARDED))
#endif
		   ) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING,
					newskb, NULL, newskb->dev,
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (ip_hdr(skb)->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, newskb,
				NULL, newskb->dev, ip_dev_loopback_xmit);
	}

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING, skb, NULL,
			    skb->dev, ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

/*
 * 对于单播数据包，目的路由缓存项中的输出接口是ip_output().
 */
int ip_output(struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev;

	IP_UPD_PO_STATS(dev_net(dev), IPSTATS_MIB_OUT, skb->len);

	/*
	 * 设置数据包的输出网络设备和数据包网络
	 * 层协议类型。
	 */
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 * 经netfilter处理后，调用ip_finish_output()继续IP数据包的输出
	 */
	return NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}

int ip_queue_xmit22(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;
	int res;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rcu_read_lock();
	rt = skb_rtable(skb);
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (rt == NULL) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->inet_daddr;
		if(opt && opt->srr)
			daddr = opt->faddr;

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .mark = sk->sk_mark,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->inet_saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .flags = inet_sk_flowi_flags(sk),
					    .uli_u = { .ports =
						       { .sport = inet->inet_sport,
							 .dport = inet->inet_dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			security_sk_classify_flow(sk, &fl);
			if (ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0))
				goto no_route;
		}
		sk_setup_caps(sk, &rt->u.dst);
	}
	skb_dst_set_noref(skb, &rt->u.dst);

packet_routed:
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->u.dst) && !skb->local_df)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;
	/* Transport layer set skb->h.foo itself. */

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->inet_daddr, rt, 0);
	}

	ip_select_ident_more(iph, &rt->u.dst, sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	res = ip_local_out(skb);
	rcu_read_unlock();
	return res;

no_route:
	rcu_read_unlock();
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}

/*
 * 在TCP中，将TCP段打包成IP数据包的方法根据TCP段类型
 * 的不同而有多种接口。其中最常用的就是ip_queue_xmit()，
 * 而ip_build_and_send_pkt()和ip_send_reply()只有在发送特定段时
 * 才会被调用。
 * @skb: 待封装成IP数据包的TCP段。
 * @ipfragok: 标识待输出的数据是否已经完成分片。由于
 * 在调用函数时ipfragok参数总为0，因此输出的IP数据包
 * 是否分片取决于是否启用PMTU发现。
 */ //TCP发送的时候从tcp_transmit_skb函数里面跳转过来
int ip_queue_xmit(struct sk_buff *skb, int ipfragok)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	/*
	 * 如果待输出的数据包已准备好路由缓存，
	 * 则无需再查找路由，直接跳转到packet_routed
	 * 处作处理。
	 */
	rt = skb_rtable(skb);
	if (rt != NULL)
		goto packet_routed;

	/* Make sure we can route this packet. */
	/*
	 * 如果输出该数据包的传输控制块中
	 * 缓存了输出路由缓存项，则需检测
	 * 该路由缓存项是否过期。
	 * 如果过期，重新通过输出网络设备、
	 * 目的地址、源地址等信息查找输出
	 * 路由缓存项。如果查找到对应的路
	 * 由缓存项，则将其缓存到传输控制
	 * 块中，否则丢弃该数据包。
	 * 如果未过期，则直接使用缓存在
	 * 传输控制块中的路由缓存项。
	 */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (rt == NULL) {
		__be32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->daddr;
		if(opt && opt->srr)
			daddr = opt->faddr;

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .mark = sk->sk_mark,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .flags = inet_sk_flowi_flags(sk),
					    .uli_u = { .ports =
						       { .sport = inet->sport,
							 .dport = inet->dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			security_sk_classify_flow(sk, &fl);
			if (ip_route_output_flow(sock_net(sk), &rt, &fl, sk, 0))
				goto no_route;
		}
		sk_setup_caps(sk, &rt->u.dst);
	}
	skb_dst_set(skb, dst_clone(&rt->u.dst));

packet_routed:
	/*
	 * 查找到输出路由后，先进行严格源路由
	 * 选项的处理。如果存在严格源路由选项，
	 * 并且数据包的下一跳地址和网关地址不
	 * 一致，则丢弃该数据包。
	 */
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto no_route;

	/* OK, we know where to send it, allocate and build IP header. */
	/*
	 * 设置IP首部中各字段的值。如果存在IP选项，
	 * 则在IP数据包首部中构建IP选项。
	 */
	skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (inet->tos & 0xff));
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;  //这里为什么是路由的src和dst ??????????????????????????????????????????//
	iph->daddr    = rt->rt_dst;
	/* Transport layer set skb->h.foo itself. */

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;
		ip_options_build(skb, opt, inet->daddr, rt, 0);
	}

	ip_select_ident_more(iph, &rt->u.dst, sk,
			     (skb_shinfo(skb)->gso_segs ?: 1) - 1);

	/*
	 * 设置输出数据包的QoS类型。
	 */
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;

	return ip_local_out(skb);

no_route:
	/*
	 * 如果查找不到对应的路由缓存项，
	 * 在此处理，将该数据包丢弃。
	 */
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	skb_dst_drop(to);
	skb_dst_set(to, dst_clone(skb_dst(from)));
	to->dev = from->dev;
	to->mark = from->mark;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
	nf_copy(to, from);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	to->nf_trace = from->nf_trace;
#endif
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	to->ipvs_property = from->ipvs_property;
#endif
	skb_copy_secmark(to, from);
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */
/*
 * 当要将一个IP数据包从本地发送或转发出去时，
 * 如果发现该IP数据包大于当前的MTU或路径MTU，
 * 则调用ip_fragment()将数据包分片后再发送出去。
 * @skb: 待分片后发送或转发的IP数据包，即原始
 *           数据包，该数据包应该包含已初始化的IP首部
 * @output:将完成分片输出的回调函数，IPv4中为
 *              ip_finish_output2().
 */
int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff *))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs, pad;
	int offset;
	__be16 not_last_frag;
	struct rtable *rt = skb_rtable(skb);
	int err = 0;

	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = ip_hdr(skb);
	
       /*
         * 如果待分片IP数据包禁止分片，则调用
         * icmp_send()向发送方发送一个原因为需要
         * 分片而设置了不分片标志的目的不可达
         * ICMP报文，并丢弃报文，即设置IP状态
         * 为分片失败，释放skb，返回消息过长
         * 错误码。
         */
	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(ip_skb_dst_mtu(skb)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	mtu = dst_mtu(&rt->u.dst) - hlen;	/* Size of data space */
#ifdef CONFIG_BRIDGE_NETFILTER
	if (skb->nf_bridge)
		mtu -= nf_bridge_mtu_reduction(skb);
#endif
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	if (skb_has_frags(skb)) {
		struct sk_buff *frag, *frag2;
		int first_len = skb_pagelen(skb);

		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||
		    skb_cloned(skb))
			goto slow_path;

		skb_walk_frags(skb, frag) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
				goto slow_path_clean;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path_clean;

			BUG_ON(frag->sk);
			if (skb->sk) {
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			skb->truesize -= frag->truesize;
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_frag_list_init(skb);
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off = htons(IP_MF);
		ip_send_check(iph);

		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->ip_summed = CHECKSUM_NONE;
				skb_reset_transport_header(frag);
				__skb_push(frag, hlen);
				skb_reset_network_header(frag);
				memcpy(skb_network_header(frag), iph, hlen);
				iph = ip_hdr(frag);
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				ip_send_check(iph);
			}

			err = output(skb);

			if (!err)
				IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		if (err == 0) {
			IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
		return err;

slow_path_clean:
		skb_walk_frags(skb, frag2) {
			if (frag2 == frag)
				break;
			frag2->sk = NULL;
			frag2->destructor = NULL;
			skb->truesize += frag2->truesize;
		}
	}

slow_path:
	left = skb->len - hlen;		/* Space per frame */
	ptr = raw + hlen;		/* Where to start from */

	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header
	 */
	pad = nf_bridge_pad(skb);
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, pad);
	mtu -= pad;

	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while (left > 0) {
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */

		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(KERN_INFO "IP: frag: no memory for new fragment!\n");
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */

		ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb_reset_network_header(skb2);
		skb2->transport_header = skb2->network_header + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */

		skb_copy_from_linear_data(skb, skb_network_header(skb2), hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		if (skb_copy_bits(skb, ptr, skb_transport_header(skb2), len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = ip_hdr(skb2);
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */
		iph->tot_len = htons(len + hlen);

		ip_send_check(iph);

		err = output(skb2);
		if (err)
			goto fail;

		IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGCREATES);
	}
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(dev_net(dev), IPSTATS_MIB_FRAGFAILS);
	return err;
}

EXPORT_SYMBOL(ip_fragment);

int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		__wsum csum = 0;
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline __wsum
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	__wsum csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

static inline int ip_ufo_append_data(struct sock *sk,
			int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
			void *from, int length, int hh_len, int fragheaderlen,
			int transhdrlen, int mtu, unsigned int flags)
{
	struct sk_buff *skb;
	int err;

	/* There is support for UDP fragmentation offload by network
	 * device, so create one single skb packet containing complete
	 * udp datagram
	 */
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL) {
		skb = sock_alloc_send_skb(sk,
			hh_len + fragheaderlen + transhdrlen + 20,
			(flags & MSG_DONTWAIT), &err);

		if (skb == NULL)
			return err;

		/* reserve space for Hardware header */
		skb_reserve(skb, hh_len);

		/* create space for UDP/IP header */
		skb_put(skb, fragheaderlen + transhdrlen);

		/* initialize network header pointer */
		skb_reset_network_header(skb);

		/* initialize protocol header pointer */
		skb->transport_header = skb->network_header + fragheaderlen;

		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum = 0;
		sk->sk_sndmsg_off = 0;

		/* specify the length of each IP datagram fragment */
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
		__skb_queue_tail(&sk->sk_write_queue, skb);
	}

	return skb_append_datato_frags(sk, skb, getfrag, from,
				       (length - transhdrlen));
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
/*
 * 如果说ip_append_data()只是UDP套接字和RAW套接字的输出接口，也不完全正确，
 * 因为在TCP中用于发送ACK和RST包的函数ip_send_reply()最终也调用了该函数。
 * ip_append_data()是一个比较复杂的函数，主要是将接收到的大数据包分成
 * 多个小于或等于MTU的SKB，为网络层要实现的IP分片做准备。例如，假设待发送
 * 的数据包大小为4000B，先前输出队列非空，且最后一个SKB还未填满，剩余500B。
 * 这时传输层调用ip_append_data(),则首先会将有剩余空间的SKB填满。当网络设备
 * 支持聚合分散I/O时，便会将数据写到frags指向的页面中，如果相关的页面已经填满，
 * 则会再分配一个新的页面。接着，进入下次循环，每次循环都分配一个SKB，
 * 通过getfrag将数据从传输层复制数据，并将其添加到输出队列的末尾，直至
 * 复制完所有待输出的数据。
 * ip_append_data()在多处被调用，包括UDP、TCP、RAW套接字以及ICMP。因此在复制数据
 * 时，有时复制传输层负载部分，传输层首部会后续添加(UDP),有时则需要复制包括
 * 传输层首部的的全部数据(ICMP).参数说明如下：
 * @sk：输出数据的传输控制块。该传输控制块还提供一些其他信息，如IP选项等。
 * @getfrag：用于复制数据到SKB中。不同的传输层，由于特性不同，因此对应复制的
 *           方法也不一样。该接口的参数说明如下：
 *           1.from：标识待复制数据存储的位置
 *           2.to：标识数据待复制到的目的地
 *           3.offset：待复制数据在数据存储位置的偏移，数据从此位置开始复制
 *           4.len：待复制数据的长度。
 *           5.odd：从上一个SKB中剩余下来并复制到此SKB中的数据长度。如果为奇数，
 *                  则后续数据的校验和计算时的16位数据的高8位和低8位的值是颠倒的，
 *                  因此需要将后续数据的校验和高低8位对调。
 *          6.skb：复制数据的SKB，计算得到的数据部分的校验和暂存到SKB中，为计算
 *                 完成的传输层校验和做准备。
 *          UDP和RAW为ip_generic_getfrag()，TCP为ip_reply_glue_bits()，ICMP为
 *          icmp_glue_bits(),复制轻量级UDP的数据时为udplite_getfrag().
 * @from：输出数据所在的数据块地址，它指向用户空间或内核空间，该参数为传递给
 *        getfrag()接口
 * @length:输出数据的长度
 * @transhdrlen：传输层首部长度
 * @ipc：传递到IP层的临时信息块
 * @rt：输出该数据的路由缓存项，在调用此函数之前由传输控制块已经缓存路由缓存
 *      项或者已经通过ip_route_output_flow()查找到了输出数据的路由缓存项
 * @flags：输出数据的一些标志，如MSG_MORE等。
 */
int ip_append_data(struct sock *sk,
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, int length, int transhdrlen,
		   struct ipcm_cookie *ipc, struct rtable **rtp,
		   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;

	struct ip_options *opt = NULL;
	int hh_len;
    /*
     * exthdrlen用于记录IPsec中扩展首部的长度，未启用IPsec时为0
     */
	int exthdrlen;
	int mtu;
	int copy;
	int err;
	int offset = 0;
	unsigned int maxfraglen, fragheaderlen;
	int csummode = CHECKSUM_NONE;
	struct rtable *rt;

    /*
     * 如果使用MSG_PROBE标识，实际上并不会进行真正的数据传递，而是
     * 进行路径MTU的探测
     */
	if (flags&MSG_PROBE)
		return 0;

    /*
     * 如果传输控制块的输出队列为空，则需要为传输控制块设置一些临时
     * 信息。
     * 如果输出数据包中存在IP选项，则将IP选项信息复制到临时信息块中，
     * 并设置IPCORK_OPT，表示临时信息块中存在IP选项。由于存在IP选项，
     * 因此需要设置临时信息块中的目的地址，因为在IP选项中存在
     * 源路由选项。
     * 同时还设置了IP数据包分片大小，输出路由缓存、初始化当前发送
     * 数据包中数据的长度（如果启用了IPsec，则还要加上IPsec首部的
     * 长度）等。
     */
	if (skb_queue_empty(&sk->sk_write_queue)) {
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		if (opt) {
			if (inet->cork.opt == NULL) {
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);
			inet->cork.flags |= IPCORK_OPT;
			inet->cork.addr = ipc->addr;
		}
		rt = *rtp;
		if (unlikely(!rt))
			return -EFAULT;
		/*
		 * We steal reference to this route, caller should not release it
		 */
		*rtp = NULL;
		inet->cork.fragsize = mtu = inet->pmtudisc == IP_PMTUDISC_PROBE ?
					    rt->u.dst.dev->mtu :
					    dst_mtu(rt->u.dst.path);
		inet->cork.dst = &rt->u.dst;
		inet->cork.length = 0;
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;
		if ((exthdrlen = rt->u.dst.header_len) != 0) {
			length += exthdrlen;
			transhdrlen += exthdrlen;
		}
	} else {
        /*
         * 如果传输控制块的输出队列不为空，则使用上次的输出路由、IP选项以及
         * 分片长度.
         */
		rt = (struct rtable *)inet->cork.dst;
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

		transhdrlen = 0;
		exthdrlen = 0;
		mtu = inet->cork.fragsize;
	}
    /*
     * 获取链路层首部及IP首部(包括选项)的长度
     */
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
    /*
     * IP数据包的数据需4字节对齐，为加速计算直接将IP数据包的数据根据当前
     * MTU 8字节对齐，然后重新得到用于分片的长度。
     */
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

    /*
     * 如果输出的数据长度超出一个IP数据包能容纳的长度，则向输出该数据包的
     * 套接字发送EMSGSIZE出错信息。
     */
	if (inet->cork.length + length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
    /*
     * 如果IP数据包没有分片，且输出网络设备支持硬件执行校验和，则设置
     * CHECKSUM_PARTIAL，表示由硬件来执行校验和。
     */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features & NETIF_F_V4_CSUM &&
	    !exthdrlen)
		csummode = CHECKSUM_PARTIAL;

    /*
     * 如果输出的是UDP数据包并且需要分片，同时输出网络设备支持UDP分片
     * 卸载（UDP fragment offload），则由ip_ufo_append_data()进行分片
     * 输出处理
     */
	inet->cork.length += length;
	if (((length> mtu) || !skb_queue_empty(&sk->sk_write_queue)) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->u.dst.dev->features & NETIF_F_UFO)) {
		err = ip_ufo_append_data(sk, getfrag, from, length, hh_len,
					 fragheaderlen, transhdrlen, mtu,
					 flags);
		if (err)
			goto error;
		return 0;
	}

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

    /*
     * 获取输出队列末尾的SKB，如果获取不到，说明输出队列为空，则需
     * 分配一个新的SKB用于复制数据。
     */
	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		goto alloc_new_skb;

    /*
     * 循环处理待输出数据包，直至所有的数据都处理完成。
     */
	while (length > 0) {
		/* Check if the remaining data fits into current packet. */
        /*
         * 检测待发送数据是否能全部复制到最后一个SKB的剩余空间中。如果可以，
         * 则说明是IP分片中的上一个分片，可以不用4字节对齐，否则需要4字节
         * 对齐，因此用8字节对齐后的MTU减去上一个SKB的数据长度，得到上一个
         * SKB的剩余空间大小，也就是本次复制数据的长度.
         * 当本次复制数据的长度copy小于等于0时，说明上一个SKB已经填满或
         * 空间不足8B，需要分配新的SKB。
         * 当copy大于0时，说明上一个SKB有剩余空间，数据可以复制到该SKB中去。
         *
         */
		copy = mtu - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;
        /*
         * 如果上一个SKB已经填满或空间不足8B，或者不存在上一个SKB，则将数据复制到
         * 新分配的SKB中去。
         */
		if (copy <= 0) {
			char *data;
            /*
             * 如果上一个SKB（通常是在调用ip_append_data()时，
             * 输出队列中最后一个SKB）中存在多余8字节对齐的MTU的数据，
             * 则这些数据需移动到当前SKB中，确保最后一个IP分片之外的
             * 数据能够4字节对齐，因此需计算移动到当前SKB的数据长度。
             */
			unsigned int datalen;
			unsigned int fraglen;
			unsigned int fraggap;
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
            /*
             * 如果剩余数据的长度超过MTU，则需要更多的分片。
             */
            /*
             * 计算需要复制到新SKB中的数据长度。因为如果前一个SKB
             * 还能容纳数据，则有一部分数据会复制到前一个SKB中。
             */
			datalen = length + fraggap;
            /*
             * 如果剩余的数据一个分片不够容纳，则根据MTU重新计算本次
             * 可发送的数据长度。
             */
			if (datalen > mtu - fragheaderlen)
				datalen = maxfraglen - fragheaderlen;
            /*
             * 根据本次复制的数据长度以及IP首部长度，计算三层
             * 首部及其数据的总长度
             */
			fraglen = datalen + fragheaderlen;

            /*
             * 如果后续还有数据要输出且网络设备不支持聚合分散I/O，则将
             * MTU作为分配SKB的长度，使分片达到最长，为后续的数据
             * 预备空间。否则按数据的长度（包括IP首部）分配SKB的空间
             * 即可。
             */
			if ((flags & MSG_MORE) &&
			    !(rt->u.dst.dev->features&NETIF_F_SG))
				alloclen = mtu;
			else
				alloclen = datalen + fragheaderlen;

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
            /*
             * 如果是最后一个分片，且是根据目的路由启用IPsec的情况，
             * 则可能需要多分配一些空间来支持IPsec。
             */
			if (datalen == length + fraggap)
				alloclen += rt->u.dst.trailer_len;


            /*
             * 根据是否存在传输层首部，确定用何种方法分配SKB。
             * 如果存在传输层首部，则可以确定该分片为分片组中的
             * 第一个分片，因此在分配SKB时需要考虑更多的情况，如
             * 输出操作是否超时,传输层是否发生未处理的致命错误，
             * 发送通道是否已关闭等。当分片不是第一个分片时，
             * 则无需考虑以上情况
             */
			if (transhdrlen) {
				skb = sock_alloc_send_skb(sk,
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk,
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
				else
					/* only the initial fragment is
					   time stamped */
					ipc->shtx.flags = 0;
			}
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
            /*
             * 填充用于校验的控制信息
             */
			skb->ip_summed = csummode;
			skb->csum = 0;
            /*
             * 为数据包预留用于存放二层首部、三层首部和数据的空间，
             * 并设置SKB中指向三层和四层的指针。
             */
			skb_reserve(skb, hh_len);
			*skb_tx(skb) = ipc->shtx;

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen);
			skb_set_network_header(skb, exthdrlen);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			data += fragheaderlen;

            /*
             * 如果上一个SKB的数据超过8字节对齐MTU，则将超出数据和
             * 传输层首部复制到当前SKB，重新计算校验和，并以8字节
             * 对齐MTU为长度截取上一个SKB的数据。
             */
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->u.dst.dev->features&NETIF_F_SG)) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy),
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			if (page && (left = PAGE_SIZE - off) > 0) {
				if (copy >= left)
					copy = left;
				if (page != frag->page) {
					if (i == MAX_SKB_FRAGS) {
						err = -EMSGSIZE;
						goto error;
					}
					get_page(page);
					skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} else if (i < MAX_SKB_FRAGS) {
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  {
					err = -ENOMEM;
					goto error;
				}
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
			} else {
				err = -EMSGSIZE;
				goto error;
			}
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			sk->sk_sndmsg_off += copy;
			frag->size += copy;
			skb->len += copy;
			skb->data_len += copy;
			skb->truesize += copy;
			atomic_add(copy, &sk->sk_wmem_alloc);
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = (struct rtable *)inet->cork.dst;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->inet_dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;
	if ((size + skb->len > mtu) &&
	    (sk->sk_protocol == IPPROTO_UDP) &&
	    (rt->u.dst.dev->features & NETIF_F_UFO)) {
		skb_shinfo(skb)->gso_size = mtu - fragheaderlen;
		skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
	}


	while (size > 0) {
		int i;

		if (skb_is_gso(skb))
			len = size;
		else {

			/* Check if the remaining data fits into current packet. */
			len = mtu - skb->len;
			if (len < size)
				len = maxfraglen - skb->len;
		}
		if (len <= 0) {
			struct sk_buff *skb_prev;
			int alloclen;

			skb_prev = skb;
			fraggap = skb_prev->len - maxfraglen;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			skb_put(skb, fragheaderlen + fraggap);
			skb_reset_network_header(skb);
			skb->transport_header = (skb->network_header +
						 fragheaderlen);
			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(skb_prev,
								   maxfraglen,
						    skb_transport_header(skb),
								   fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				pskb_trim_unique(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			__wsum csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		skb->truesize += len;
		atomic_add(len, &sk->sk_wmem_alloc);
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}

static void ip_cork_release(struct inet_sock *inet)
{
	inet->cork.flags &= ~IPCORK_OPT;
	kfree(inet->cork.opt);
	inet->cork.opt = NULL;
	dst_release(inet->cork.dst);
	inet->cork.dst = NULL;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = (struct rtable *)inet->cork.dst;
	struct iphdr *iph;
	__be16 df = 0;
	__u8 ttl;
	int err = 0;

	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb_network_header(skb))
		__skb_pull(skb, skb_network_offset(skb));
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		__skb_pull(tmp_skb, skb_network_header_len(skb));
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	if (inet->pmtudisc < IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc >= IP_PMTUDISC_DO ||
	    (skb->len <= dst_mtu(&rt->u.dst) &&
	     ip_dont_fragment(sk, &rt->u.dst)))
		df = htons(IP_DF);

	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	iph->ihl = 5;
	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}
	iph->tos = inet->tos;
	iph->frag_off = df;
	ip_select_ident(iph, &rt->u.dst, sk);
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	/*
	 * Steal rt from cork.dst to avoid a pair of atomic_inc/atomic_dec
	 * on dst refcount
	 */
	inet->cork.dst = NULL;
	skb_dst_set(skb, &rt->u.dst);

	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	/* Netfilter gets whole the not fragmented skb. */
	err = ip_local_out(skb);
	if (err) {
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			goto error;
	}

out:
	ip_cork_release(inet);
	return err;

error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	ip_cork_release(inet_sk(sk));
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset,
			      int len, int odd, struct sk_buff *skb)
{
	__wsum csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;
}

/*
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock
 *     	structure to pass arguments.
 */
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	__be32 daddr;
	struct rtable *rt = skb_rtable(skb);

	if (ip_options_echo(&replyopts.opt, skb))
		return;

	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;
	ipc.shtx.flags = 0;

	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

	{
		struct flowi fl = { .oif = arg->bound_dev_if,
				    .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(ip_hdr(skb)->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = tcp_hdr(skb)->dest,
						 .dport = tcp_hdr(skb)->source } },
				    .proto = sk->sk_protocol,
				    .flags = ip_reply_arg_flowi_flags(arg) };
		security_skb_classify_flow(skb, &fl);
		if (ip_route_output_key(sock_net(sk), &rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	inet->tos = ip_hdr(skb)->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = ip_hdr(skb)->protocol;
	sk->sk_bound_dev_if = arg->bound_dev_if;
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, &rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((__sum16 *)skb_transport_header(skb) +
			  arg->csumoffset) = csum_fold(csum_add(skb->csum,
								arg->csum));
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

void __init ip_init(void)
{
	ip_rt_init();
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);

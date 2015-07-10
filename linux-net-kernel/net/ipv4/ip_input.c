/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	Process Router Attention IP option
 */
int ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;

	read_lock(&ip_ra_lock);
	for (ra = ip_ra_chain; ra; ra = ra->next) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), dev_net(dev))) {
			if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
				if (ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN)) {
					read_unlock(&ip_ra_lock);
					return 1;
				}
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		read_unlock(&ip_ra_lock);
		return 1;
	}
	read_unlock(&ip_ra_lock);
	return 0;
}

//从这里进入L4传输层
/*
 * ip_local_deliver_finish()将输入数据包从网络层传递
 * 到传输层。过程如下:
 * 1)首先，在数据包传递给传输层之前，去掉IP首部
 * 2)接着，如果是RAW套接字接收数据包，则需要
 * 复制一份副本，输入到接收该数据包的套接字。
 * 3)最后，通过传输层的接收例程，将数据包传递
 * 到传输层，由传输层进行处理。
 */
static int ip_local_deliver_finish(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);

	/*
	 * 在数据包传递给传输层之前，先去掉
	 * IP首部。
	 */
	__skb_pull(skb, ip_hdrlen(skb));

	/* Point into the IP datagram, just past the header. */
       /* "删除"IP 首部*/
	skb_reset_transport_header(skb);

	rcu_read_lock();
	{     /* 获取该IP包承载的上层协议,也就是传输层协议号，用于计算后面的hash*/
		int protocol = ip_hdr(skb)->protocol;
		int hash, raw;
		const struct net_protocol *ipprot;

	resubmit:
		/*
		 * 处理RAW套接字，先根据传输层协议号
		 * 得到哈希值，然后查看raw_v4_htable散列表
		 * 中以该值为关键字的哈希桶是否为空，
		 * 如果不为空，则说明创建了RAW套接字，
		 * 复制该数据包的副本输入到注册到
		 * 该桶中的所有套接字。
		 */
/*
ip_local_deliver_finish函数会先检查哈希表raw_v4_htable。因为在创建 socket时，inet_create会把协议号IPPROTO_ICMP的值赋给socket的成员num，
并以num为键值，把socket存入哈 项表raw_v4_htable，raw_v4_htable[IPPROTO_ICMP&(MAX_INET_PROTOS-1)]上即存放了 这个socket，实际上是一个socket的链表，
如果其它还有socket要处理这个回显应答，也会被放到这里，组成一个链 表，ip_local_deliver_finish收到数据报后，取出这个socket链表(目前实际上只有一项)，
调用raw_v4_input，把 skb交给每一个socket进行处理。然后，还需要把数据报交给inet_protos[IPPROTO_ICMP& (MAX_INET_PROTOS-1)]，即icmp_rcv处理，
因为对于icmp报文，每一个都是需要经过协议栈处理的，但对回显应 答，icmp_rcv只是简单丢弃，并未实际处理。
*/
		 ////之前开巨帧的时候，icmp不通就是在这里面的函数中sock_queue_rcv_skb丢的
		raw = raw_local_deliver(skb, protocol); //如果是raw套接字，则则该函数里面会复制一份skb，然后送到，例如用ping 1.2.2.2的时候，会走这里面，不会走icmp_recv

		hash = protocol & (MAX_INET_PROTOS - 1);
		ipprot = rcu_dereference(inet_protos[hash]);
		/*
		 * 通过查找inet_portos数组，确定是否
		 * 注册了与IP首部中传输层协议号
		 * 一致的传输层协议。若查找命中，
		 * 则执行对应的传输层协议例程。
		 */
		if (ipprot != NULL) {
			int ret;

			if (!net_eq(net, &init_net) && !ipprot->netns_ok) {
				if (net_ratelimit())
					printk("%s: proto %d isn't netns-ready\n",
						__func__, protocol);
				kfree_skb(skb);
				goto out;
			}

			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			ret = ipprot->handler(skb);//这里面会进入udp tcp传输层去
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			/*
			 * 如果没有响应的协议传输层接收该数据包，
			 * 则释放该数据包。在释放前，如果是RAW
			 * 套接字没有接收或接收异常，则还需产生
			 * 一个目的不可达ICMP报文给发送方。表示该包raw没有接收并且inet_protos中没有注册该协议
			 */
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
			} else
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
			kfree_skb(skb);
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}


/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
 /*
  * 在ip_route_input进行路由选择后，如果接收的包
  * 是发送给本机，则调用ip_local_deliver来传递给上层协议
  */
  //ip_route_input_slow->ip_local_deliver
int ip_local_deliver(struct sk_buff *skb)
{
    /*
     *  Reassemble IP fragments.
     */
        /* 
         * frag_off是16位，其中高3位用作标志位，
         * 低13位才是真正的偏移量.
         * 内核可通过设置的分片标识位或非0
         * 的分片偏移量识别分片的分组。偏移
         * 量字段为0，表明这是分组的最后一个分片。
         * 
         * 如果接收到的IP数据包时分片，则调用
         * ip_defrag()进行重组，其标志位IP_DEFRAG_LOCAL_DELIVER。
         */
    if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
       /*
        * 重新组合分片分组的各个部分。
        * 
        * 如果ip_defrag()返回非0，则表示IP数据包分片
        * 尚未到齐，重组没有完成，或者出错，直接
        * 返回。为0，则表示已完成IP数据包的重组，
        * 需要传递到传输层进行处理。
        */
        if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
            return 0;
    }

    /*
     * 经过netfilter处理后，调用ip_local_deliver_finish()，
     * 将组装完成的IP数据包传送到传输层处理
     */
    return NF_HOOK(PF_INET, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
               ip_local_deliver_finish);
}


static inline int ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = in_dev_get(dev);
		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev) &&
				    net_ratelimit())
					printk(KERN_INFO "source route option %pI4 -> %pI4\n",
					       &iph->saddr, &iph->daddr);
				in_dev_put(in_dev);
				goto drop;
			}

			in_dev_put(in_dev);
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return 0;
drop:
	return -1;
}

/*
 * ip_rcv_finish()在ip_rcv()中当IP数据包经过netfilter模块
 * 处理后被调用。完成的主要功能是，如果
 * 还没有为该数据包查找输入路由缓存，则
 * 调用ip_route_input()为其查找输入路由缓存。
 * 接着处理IP数据包首部中的选项，最后
 * 根据输入路由缓存输入到本地或抓发。
 */
static int ip_rcv_finish(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	/*
	 * 如果还没有为该数据包查找输入路由缓存，
	 * 则调用ip_route_input()为其查找输入路由缓存。
	 * 若查找失败，则将该数据包丢弃。
	 */
	if (skb_dst(skb) == NULL) {
              /* 选择路由*/
		int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
					 skb->dev);//最终会调用ip_local_deliver
		if (unlikely(err)) {
			if (err == -EHOSTUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
						IPSTATS_MIB_INADDRERRORS);
			else if (err == -ENETUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
						IPSTATS_MIB_INNOROUTES);
			goto drop;
		}
	}

#ifdef CONFIG_NET_CLS_ROUTE
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = per_cpu_ptr(ip_rt_acct, smp_processor_id());
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	/*
	 * 根据长度判断IP首部中是否存在选项，如果有，
	 * 则调用ip_rcv_options()处理IP选项。
	 */
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INMCAST,
				skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INBCAST,
				skb->len);

	/*
	 * 最后根据输入路由缓存决定输入到本地或
	 * 转发，最终前者调用ip_local_deliver()，后者调用
	 * ip_forward()。
	 * 对于输入到本地或转发的组播报文，在经过netfilter处理
	 * 之后会调用ip_rcv_finish()正式进入输入的处理。先调用
	 * ip_route_input()进行输入路由的查询，如果发现目的地址
	 * 为组播地址，就会按照组播地址的规则查找路由，查找
	 * 到组播的输入路由后，组播报文接收处理函数为ip_mr_input()。
	 * 参见ip_route_input_mc().
	 */
	return dst_input(skb);//ip_route_input->ip_route_input_common->ip_route_input_slow中有注册  ip_local_deliver;//到本地  ip_forward转发

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

EXPORT_SYMBOL_GPL(ip_rcv_finish);

extern int dev_d1300;
/*
 * 	Main IP Receive routine.
 yang add
 在上一节可以看到，链路层将数据包上传到IP层时，由IP层相关协议的处理例程处理。对于IP协议，这个注册的处理例程是ip_rcv()，它处理
 完成后交给NETFILTE（PRE-ROUTING）R过滤，再上递给ip_rcv_finish(), 这个函数根据skb包中的路由信息，决定这个数据包是转发还是上交
 给本机，由此产生两条路径，一为ip_local_deliver()，它首先检查这个包是否是一个分片包，如果是，它要调动ip_defrag()将分片重装，
 然后再次将包将给NETFILTER（LOCAL_IN）过滤后，再由ip_local_deliver_finish()将数据上传到L4层，这样就完成了IP 层的处理；它
 负责将数据上传，另一路径为ip_forward()，它负责将数据转发，经由NETFILTER（FORWARD）
 过滤后将给ip_forward_finish()，然后调用dst_output()将数据包发送出去。

 http://blog.sina.com.cn/s/blog_6857a06f0100ljs4.html
 以下是我根据 linux-2.6.23.9版本内核源代码所做阅读笔记，属个人兴趣而为，希望找到有共同兴趣
的朋友一起讨论和研究，有谬误之处，笔者水平有限，欢迎大家拍砖：）
------------------------------------------------------------------------------------------

|----------------------------------| 

         应用层

|----------------------------------|

　    BSD Socket层

|----------------------------------|　

      Inet Socket层

|----------------------------------|

      IP层

|----------------------------------|

  数据链路/硬件层

|----------------------------------|

IP层：          IP协议栈的实现，完成路由的查找过程(主要处理skb)
Inet Socket层： 对IP包进行分组排序，实现QoS,传输层协议TCP/UDP协议栈的实现
　　　　　　    使用sock{}类型数据来管理会话，数据主要放在sk_buff结构中　　　
BSD Socket:     对于BSD Socket相关调用的实现,主要使用socket{}结构来存放连接
                数据主要是放在msghdr{}结构中

参考:http://www.2cto.com/Article/201206/136644.html
 ip_rcv函数。该函数主要用来处理网络层的IP报文的入口函数，它到Netfilter框架的切入点为：
 NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, dev, NULL,ip_rcv_finish)
 根据前面的理解，这句代码意义已经很直观明确了。那就是：如果协议栈当前收到了一个IP报文(PF_INET)，那么就把这个报文传到Netfilter
 的NF_IP_PRE_ROUTING过滤点，去检查[R]在那个过滤点(nf_hooks[2][0])是否已经有人注册了相关的用于处理数据包的钩子函数。如果有，
 则挨个去遍历链表nf_hooks[2][0]去寻找匹配的match和相应的target，根据返回到Netfilter框架中的值来进一步决定该如何处理该数据包
 (由钩子模块处理还是交由ip_rcv_finish函数继续处理)。
 
 [R]：刚才说到所谓的“检查”。其核心就是nf_hook_slow()函数。该函数本质上做的事情很简单，根据优先级查找双向链表nf_hooks[][]，
 找到对应的回调函数来处理数据包：

 最后,数据包会传到l3层,如果是ip协议,则相应的处理函数为ip_rcv,到此数据报从网卡到l3层的接收过程已经完毕.即总的路线是: 
 netif_rx-->net_rx_action-->process_backlog-->netif_receive_skb-- >sniffer(如果有)-->diverter(如果有)-->bridge(如果有)-->ip_rcv(或者其他的l3 层协议处理函数)
 */
 /*
接收数据包的下半部处理流程为：
net_rx_action // 软中断
    |--> process_backlog() // 默认poll
               |--> __netif_receive_skb() // L2处理函数
                            |--> ip_rcv() // L3入口

*/

/*
 * 	Main IP Receive routine.
 * @skb: 接收到的IP数据包
 * @dev: 接收到的IP数据包当前的输入网络设备
 * @pt:输入此数据包的网络层输入接口
 * @orig_dev:接收到的IP数据包原始的输入网络设备。
 */
 //在data指针移动size(iphdr)后，移动到指向传输层的函数是ip_local_deliver_finish
 //如果有发送到本地的数据包，本地收到后可能需要从组，在函数ip_local_deliver中从组
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;//定义一个ip报文的数据报头
	u32 len;

	if((0 == dev_d1300) || (dev->name[3] != '2')) {
		/* When the interface is in promisc. mode, drop all the crap
		 * that it receives, do not try to analyse it.
		 */
		if (skb->pkt_type == PACKET_OTHERHOST) //数据包不是发给我们的,这里所说的“不属于”这个主机，是指在这个包目标主机的MAC地址不是本机，而不是L3层的ip地址。
			goto drop;
	}


	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len); 

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {//接下来是一个共享的检查，如果是共享的数据包，因为它可能需要修改skb中的信息，所以要先复制一个副本，再作进一步的处理。
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))//再下来就是检查首部的长度是否够长，校检和等等：
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;
/*
//iph->ihl<5说明iph->ihl指的是IP包的首部长度，首部一行是32bit也就是4byte（字节）注：1byte=8bit，byte是计算机中最小文件
单位，普通IP数据包首部长度（不包含任何选项）字段的值是5.*/
	if (!pskb_may_pull(skb, iph->ihl*4))//对数据报的头长度进行检查  //iph->ihl*4是20，是首部最长的长度,此语句是说如果头部长度不能pull，则error
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto inhdr_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len)) {//根据ip包总长度，重新计算skb的长度，去掉末尾的无用信息
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));//这里面后面会存ip填充信息，IP如果超过20字节，就有填充信息

	/* Must drop socket now because of tproxy. */
	/*
	 * 将skb中的IP控制块清零，以便
	 * 后续对IP选项的处理
	 */
	skb_orphan(skb);

    /*
         * 最后通过netfilter模块处理后，调用ip_rcv_finish()
         * 完成IP数据包的输入。
         */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish); //hook注册地方在nf_register_hooks

inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

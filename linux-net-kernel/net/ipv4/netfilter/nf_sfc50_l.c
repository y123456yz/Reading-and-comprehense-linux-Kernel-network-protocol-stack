#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>

#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netfilter/nf_conntrack.h>
#endif
#include <net/netfilter/nf_conntrack_zones.h>

#include "nf_sfc50_l_data.h"
#include "nf_gate_data.h"
#include "decode.h"

#ifdef DEBUG
#define SFC50_L_DBG(x) x
#else
#define SFC50_L_DBG(x)
#endif

#ifdef DBG_WARNING
#define SFC50_L_WARN(x) x
#else
#define SFC50_L_WARN(x)
#endif

static unsigned int loopback_ip = (127 << 24)
								| (0 << 16)
								| (0 << 8)
								| 0;

static inline void sfc50_l_l4_checksum(struct iphdr *oldiph)
{
    if(oldiph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph;
		int datalen;

		datalen = ntohs(oldiph->tot_len) - (oldiph->ihl << 2);
		tcph = (struct tcphdr *)((unsigned char *)oldiph + (oldiph->ihl << 2));
		tcph->check = 0;
		tcph->check = tcp_v4_check(datalen,
					   oldiph->saddr, oldiph->daddr,
					   csum_partial(tcph,
							datalen, 0));
	}
	else if(oldiph->protocol == IPPROTO_UDP) {
		struct udphdr *udph;
		int datalen;

		udph = (struct udphdr *)((unsigned char *)oldiph + (oldiph->ihl << 2));
		if(udph->check) {
			datalen = ntohs(oldiph->tot_len) - (oldiph->ihl << 2);
			udph->check = 0;
			udph->check = csum_tcpudp_magic(oldiph->saddr, oldiph->daddr,
												datalen, IPPROTO_UDP,
												csum_partial(udph,
													     datalen, 0));
		}
	}
}

/* 发送流程入口 */
static unsigned int sfc50_l_hook_out(unsigned int hooknum,
					  struct sk_buff *skb,
					  const struct net_device *in,
					  const struct net_device *out,
					  int (*okfn)(struct sk_buff *))
{
	struct iphdr *oldiph, *newiph;
	unsigned int max_headroom;
	struct sk_buff *new_skb;
	unsigned int newip;

	if(!sfc_dt.is_online)
		return NF_ACCEPT;

	oldiph = ip_hdr(skb);

	/* loopback */
	if(loopback_ip == (loopback_ip & ntohl(oldiph->saddr))
		|| loopback_ip == (loopback_ip & ntohl(oldiph->daddr))) {
		SFC50_L_DBG(printk(KERN_DEBUG "tx: loopback pkt, skip it!!!\n"););
		return NF_ACCEPT;
	}

	/* UDP/TCP only */
	if(unlikely(IPPROTO_UDP != oldiph->protocol
		&& IPPROTO_TCP != oldiph->protocol
		&& IPPROTO_ICMP != oldiph->protocol))
		return NF_ACCEPT;

	/* 不处理分片 */
	if(unlikely(oldiph->frag_off & htons(IP_OFFSET))) {
		SFC50_L_WARN(printk(KERN_WARNING "rx: rcv ip frag, skip it!!!\n"););
		return NF_ACCEPT;
	}

	if(unlikely(!pskb_may_pull(skb, ntohs(oldiph->tot_len)))) {
		SFC50_L_WARN(printk(KERN_DEBUG "<%s, %d>: rx: length skb error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_ACCEPT;
	}

	/* 工作模式 */
	if(sfc_dt.mode & (1 << SFC50_L_M_NET)) {
		if((ntohl(oldiph->daddr) & sfc_dt.mask)
			== sfc_dt.prefix)
			return NF_ACCEPT;
	}
	if(sfc_dt.mode & (1 << SFC50_L_M_WHITE)) {
		if(mtrie_longest_match(sfc_dt.w_root,
			ntohl(oldiph->daddr))) {
			return NF_ACCEPT;
		}
	}

	/* 要排除一种情况: 宿主主机发送的、目的是本机ID的报文，
	应当由D100返回给宿主主机 */
	if(sfc_dt.id == ntohl(oldiph->daddr)) {
    	SFC50_L_WARN(printk(KERN_WARNING "<%s, %d>: loopback to host, id=%08x, sip=%08x\n",
			__FILE__, __LINE__, sfc_dt.id, ntohl(oldiph->saddr)););
	    newip = oldiph->daddr;
	    oldiph->daddr = oldiph->saddr;
	    oldiph->saddr = newip;
	    sfc50_l_l4_checksum(oldiph);
		ip_send_check(oldiph);
			return NF_ACCEPT;
		}

	/* 网关查询 */
	sfc50_l_data_lock();
	if(NF_DROP == sfc50_l_gw_find(skb, oldiph, &newip)) {
		sfc50_l_data_unlock();
		return NF_DROP;
	}
	sfc50_l_data_unlock();

	/* 开始封装 */
	max_headroom = sizeof(struct iphdr) + MTP_AUTH_INFO_LEN + LL_MAX_HEADER;
	new_skb = skb_realloc_headroom(skb, max_headroom);
	if (!new_skb) {
		SFC50_L_WARN(printk(KERN_WARNING "<%s, %d>: no memory!!!\n",
			__FILE__, __LINE__););
		return NF_DROP;
	}
	if (skb->sk)
		skb_set_owner_w(new_skb, skb->sk);
	skb = new_skb;
	oldiph = ip_hdr(skb);

	skb_push(skb, sizeof(struct iphdr) + MTP_AUTH_INFO_LEN);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	newiph 				=	ip_hdr(skb);
	memcpy(newiph, oldiph, sizeof(struct iphdr));
	newiph->protocol	=	sfc_dt.is_inside ? IPPROTO_MTP_I : IPPROTO_MTP_O;
	newiph->daddr		=	newip; /* saddr is local ip address */
	newiph->tot_len		=	htons(ntohs(oldiph->tot_len) + sizeof(struct iphdr) + MTP_AUTH_INFO_LEN);
	newiph->ihl			=	5;

	if((ntohl(oldiph->daddr) & 0xdc000000) == 0xdc000000) {
		oldiph->saddr = htonl(sfc_dt.id); /* set local ID */
		ip_send_check(oldiph);
	}

	if(sfc_dt.is_inside) {
		memset((unsigned char *)newiph + sizeof(struct iphdr),
			0, MTP_AUTH_INFO_LEN); /* 起源认证信息 */
	}
	else {
		struct scatterlist sg;
		
		if(crypto_hash_init(&(sfc_dt.md5))) {
			printk(KERN_ALERT "<%s, %d>: MD5 init failed !!!\n",
				__FILE__, __LINE__);
			goto crypto_er;
		}

		sg_init_one(&sg, oldiph, sizeof(struct iphdr));
		if(crypto_hash_update(&(sfc_dt.md5), &sg, sizeof(struct iphdr))) {
			printk(KERN_ALERT "<%s, %d>: MD5 update failed !!!\n",
				__FILE__, __LINE__);
			goto crypto_er;
		}

		sg_init_one(&sg, &(sfc_dt.key), sizeof(int));
		if(crypto_hash_update(&(sfc_dt.md5), &sg, sizeof(int))) {
			printk(KERN_ALERT "<%s, %d>: MD5 update failed !!!\n",
				__FILE__, __LINE__);
			goto crypto_er;
		}

		if(crypto_hash_final(&(sfc_dt.md5), (unsigned char *)newiph
			+ sizeof(struct iphdr))) {
			printk(KERN_ALERT "<%s, %d>: MD5 final failed !!!\n",
				__FILE__, __LINE__);
			goto crypto_er;
		}
	}

	/* l4 checksum */
	sfc50_l_l4_checksum(oldiph);

	/* checksum already */
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (unlikely(ip_route_me_harder(skb, RTN_LOCAL))) {
		dev_kfree_skb(skb);
		SFC50_L_WARN(printk(KERN_WARNING "<%s, %d>: route failed!!!\n",
			__FILE__, __LINE__););
		return NF_DROP;
	}

	/* ip checksum here */
	ip_local_out(skb);
	
	return NF_DROP;

crypto_er:
	dev_kfree_skb(skb);
	return NF_DROP;
}

/*- 接收流程 -*/
/* erp rx */
static unsigned int sfc50_l_erp_rx(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct icmphdr *icmph;
	__sum16	checksum;

	return NF_ACCEPT; //for now, skip it
	
	iph = ip_hdr(skb);
	
	if(unlikely(!pskb_may_pull(skb, ntohs(iph->tot_len)))) {
		SFC50_L_DBG(printk(KERN_DEBUG "<%s, %d>: rx: length skb error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_DROP;
	}

	if(unlikely(ntohs(iph->tot_len) <= (iph->ihl << 2) +
		sizeof(struct icmphdr) + sizeof(struct iphdr))) {
		SFC50_L_WARN(printk(KERN_DEBUG "<%s, %d>: rx: length skb error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_DROP;
	}

	/* ICMP检查 */
	icmph = (struct icmphdr *)((unsigned char *)iph + (iph->ihl << 2));
	checksum = icmph->checksum;
	icmph->checksum = 0;
	icmph->checksum = ip_compute_csum((void *)icmph, 
		ntohs(iph->tot_len) - (iph->ihl << 2));
	if(unlikely(checksum != icmph->checksum)) {
		SFC50_L_DBG(printk(KERN_DEBUG "<%s, %d>: rx: bad erp checksum, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_DROP;
	}

	/* 不可达原始IP头 */
	iph = (struct iphdr *)((unsigned char *)iph + (iph->ihl << 2) +
		sizeof(struct icmphdr));

	/* 仅仅内网角色，需要通知用户空间 */
	if(sfc_dt.is_inside) {
		sfc50_l_data_send(ntohl(iph->daddr));
		SFC50_L_DBG(printk(KERN_DEBUG "<%s, %d>: ERP rx, notify user-space unreach: <dst:%08x>\n",
			__FILE__, __LINE__, ntohl(iph->daddr)););
	}

	/* cache 反馈 */
	sfc50_l_data_lock();
	sfc50_l_cache_feedback(iph);
	sfc50_l_data_unlock();

	SFC50_L_DBG(printk(KERN_DEBUG "<%s, %d>: ERP rx, to local stack: <dst:%08x>\n",
		__FILE__, __LINE__, ntohl(iph->daddr)););

	return NF_ACCEPT;
}

/* mtp rx */
static unsigned int sfc50_l_mtp_rx(struct sk_buff *skb)
{
	struct pintercept_pkthdr pkthdr;
	Packet p;
	struct iphdr *iphdr;
	unsigned short oiph_len, ototal_len, pull_len;

	/* pkt valid */
	iphdr = ip_hdr(skb);
	oiph_len = iphdr->ihl << 2;
	ototal_len = ntohs(iphdr->tot_len);

	if(unlikely(ototal_len <= oiph_len + MTP_AUTH_INFO_LEN + sizeof(struct iphdr))) {
		SFC50_L_WARN(printk(KERN_DEBUG "<%s, %d>: rx: length skb error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_ACCEPT;
	}

	if(unlikely(!pskb_may_pull(skb, ototal_len))) {
		SFC50_L_WARN(printk(KERN_DEBUG "<%s, %d>: rx: length skb error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_ACCEPT;
	}

	/* make a ip eth frame */
	pull_len = oiph_len + MTP_AUTH_INFO_LEN - ETHERNET_HEADER_LEN;
	skb_pull(skb, pull_len);

	/* pintercept_pkthdr ready */
	pkthdr.len = ototal_len - pull_len;
	pkthdr.caplen = pkthdr.len;

	/* p */
	memset(&p, 0, sizeof(p));
	p.skb = skb;
	
	if(unlikely(NF_DROP == DecodeEthPkt(&p, &pkthdr, skb->data))) {
		SFC50_L_WARN(printk(KERN_DEBUG "<%s, %d>: rx: real pkt check error, drop it !!!\n",
			__FILE__, __LINE__););
		return NF_ACCEPT;
	}

	skb_pull(skb, ETHERNET_HEADER_LEN); /* skip eth layer */
	skb_reset_network_header(skb); /* set ip layer */
	iphdr = ip_hdr(skb);
	skb_set_transport_header(skb, iphdr->ihl << 2); /* set transport layer */
	
	//printk("<%s, %d>: rx OK: src=%08x, dst=%08x, proto=%u\n",
	//	__FILE__, __LINE__, ntohl(iphdr->saddr),
	//	ntohl(iphdr->daddr), iphdr->protocol);
	
	return NF_ACCEPT;
}

/* 接收流程入口 */
static unsigned int sfc50_l_hook_in(unsigned int hooknum,
					  struct sk_buff *skb,
					  const struct net_device *in,
					  const struct net_device *out,
					  int (*okfn)(struct sk_buff *))
{
	/* loopback */
	if(loopback_ip == (loopback_ip & ntohl(ip_hdr(skb)->saddr))
		|| loopback_ip == (loopback_ip & ntohl(ip_hdr(skb)->daddr))) {
		SFC50_L_DBG(printk(KERN_DEBUG "rx: loopback pkt, skip it!!!\n"););
		return NF_ACCEPT;
	}
	
	/* 不处理分片 */
	if(unlikely(ip_hdr(skb)->frag_off & htons(IP_OFFSET))) {
		SFC50_L_WARN(printk(KERN_WARNING "rx: rcv ip frag, skip it!!!\n"););
		return NF_ACCEPT;
	}
	
	/* Must be online */
	if(!sfc_dt.is_online)
		return NF_ACCEPT;

	/* MTP decode */
	if(IPPROTO_MTP_O == ip_hdr(skb)->protocol
		|| IPPROTO_MTP_I == ip_hdr(skb)->protocol)
	return sfc50_l_mtp_rx(skb);

	/* ERP decode */
	if(IPPROTO_ERP == ip_hdr(skb)->protocol) 
		return sfc50_l_erp_rx(skb);

	/* ignore other pkt */
	return NF_ACCEPT;
}

static struct nf_hook_ops ipv4_sfc50_l_ops[] = {
#if 0
	{
		.hook		= sfc50_l_hook_out,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_SFC50_L_OUT,
	},
#endif
	{
		.hook		= sfc50_l_hook_out,//sfc50_l_hook_check,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_SFC50_L_OUT,
	},
	{
		.hook		= sfc50_l_hook_in,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_SFC50_L_IN,
	},
};

static int __init nf_sfc50_l_init(void)
{
	int ret;

	ret = nf_register_hooks(ipv4_sfc50_l_ops, ARRAY_SIZE(ipv4_sfc50_l_ops));
	if(ret < 0) {
		printk(KERN_ERR "<%s, %s, %d>: !!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto failed_out0;
	}
	
	printk(KERN_INFO "sfc50_l module: init done.\n");

	return 0;

failed_out0:
	return -1;
}

static void __exit nf_sfc50_l_fini(void)
{
	nf_unregister_hooks(ipv4_sfc50_l_ops, ARRAY_SIZE(ipv4_sfc50_l_ops));
	
	printk(KERN_INFO "sfc50_l module: uninit done.\n");
}

module_init(nf_sfc50_l_init);
module_exit(nf_sfc50_l_fini);

MODULE_LICENSE("GPL");



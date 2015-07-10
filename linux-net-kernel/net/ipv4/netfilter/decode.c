/* $Id: decode.c,v 1.6 2010/05/17 06:29:25 cailiyang Exp $ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>

#include "snrt_checksum.h"
#include "decode.h"
#include "sigf_hook.h"

#ifdef DEBUG
#define DECODE_DBG(x) x
#else
#define DECODE_DBG(x)
#endif

#ifdef DBG_WARNING
#define DECODE_WARN(x) x
#else
#define DECODE_WARN(x)
#endif


extern int shpkt_rcv(sigf_info_t *sf);


grinder_t grinder = DecodeEthPkt;
EXPORT_SYMBOL_GPL(grinder);

int g_drop_pkt = 0;        /* inline drop pkt flag */ 
EXPORT_SYMBOL_GPL(g_drop_pkt);
int g_skip_pkt = 0;        /* inline drop pkt flag */ 
EXPORT_SYMBOL_GPL(g_skip_pkt);

void _InlineDrop_(void)
{
	g_drop_pkt = 1;
}
EXPORT_SYMBOL_GPL(_InlineDrop_);

void _InlineSkip_(void)
{
	g_skip_pkt = 1;
}
EXPORT_SYMBOL_GPL(_InlineSkip_);

void DebugMessageFunc(int level, char * file, int line, char *fmt, ...)
{
    va_list ap;
    char buf[STD_BUF+1];
    int ptr = 0;

    /* filename and line number information */
    if (file != NULL)
        ptr = sprintf(buf, "<%s, %d>: ", file, line);

    va_start(ap, fmt);

    ptr += vsnprintf(buf + ptr, STD_BUF, fmt, ap);
    strcat(buf, "\r\n");
    printk(buf);

    va_end(ap);
}
EXPORT_SYMBOL_GPL(DebugMessageFunc);

#if 0
char *snort_strdup(char *str)
{
	char *ret;
	
	if(NULL == str)
		return NULL;

	ret = kmalloc(strlen(str) + 1, GFP_ATOMIC);
	if(NULL == ret) {
		return NULL;
	}

	strcpy(ret, str);

	return ret;
}
EXPORT_SYMBOL_GPL(snort_strdup);
#endif
/*
 * Function: DecodeEthPkt(Packet *, char *, struct pcap_pkthdr*, u_int8_t*)
 *
 * Purpose: Decode those fun loving ethernet packets, one at a time!
 *
 * Arguments: p => pointer to the decoded packet struct
 *            user => Utility pointer (unused)
 *            pkthdr => ptr to the packet header
 *            pkt => pointer to the real live packet data
 *
 * Returns: void function
 */
 //pkt指向为实际数据部分的前ETHERNET_HEADER_LEN，就是用AUTH的后ETHERNET_HEADER_LEN字节补充为ETH头部， 函数最后的DecodeIP会在向前移动ETHERNET_HEADER_LEN字节
//对IP层 TCP层或者UDP层或者ICMP层进行校验，注意实际的ETH填充在该函数外面
unsigned int DecodeEthPkt(Packet * p, struct pintercept_pkthdr * pkthdr, u_int8_t * pkt)
{
    u_int32_t pkt_len;      /* suprisingly, the length of the packet */
    u_int32_t cap_len;      /* caplen value */

    //memset((char *)p, 0, sizeof(Packet));

    p->pkth = pkthdr;
    p->pkt = pkt;

    /* set the lengths we need */
    pkt_len = pkthdr->len;  /* total packet length */
    cap_len = pkthdr->caplen;   /* captured packet length */

    if(cap_len < pkt_len)
        pkt_len = cap_len;

    /* do a little validation */
    if(cap_len < ETHERNET_HEADER_LEN)
    {
		DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: too short, len = %d\n",
					__FILE__, __LINE__, cap_len););
        return NF_DROP;
    }

    /* lay the ethernet structure over the packet data */
    p->eh = (EtherHdr *) pkt;

	return DecodeIP(p->pkt + ETHERNET_HEADER_LEN, 
					cap_len - ETHERNET_HEADER_LEN, p);//这里又向后移动了ETHERNET_HEADER_LEN字节的数据，指向了实际数据的IP层
}
EXPORT_SYMBOL_GPL(DecodeEthPkt);

/*
 * Function: DecodeIP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the IP network layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the packet decode struct
 *
 * Returns: void function
 */

//yang  如果是分片包的一部分，返回NF_STOLEN                   对IP层、TCP层或者UDP层进行校验
unsigned int DecodeIP(u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    u_int32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    u_int32_t hlen;   /* ip header length */
    u_int16_t csum;   /* checksum */

    /* lay the IP struct over the raw data */
    p->iph = (IPHdr *) pkt;

    if(unlikely(len < IP_HEADER_LEN)) {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: -------------->  too short, len = %u <-----------------\n",
				__FILE__, __LINE__, len););
    	return NF_DROP;
    }

    if(IP_VER(p->iph) != 4) {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: -------------->  ip ver dismatch, ver = %d <-----------------\n",
				__FILE__, __LINE__, IP_VER(p->iph)););
    	return NF_DROP;
    }

    /* set the IP datagram length */
    ip_len = ntohs(p->iph->ip_len);

    /* set the IP header length */
    hlen = IP_HLEN(p->iph) << 2;

    if(hlen < IP_HEADER_LEN)
    {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: -------------->  ip hdr too short, len = %u <-----------------\n",
				__FILE__, __LINE__, hlen););
    	return NF_DROP;
    }

    if(ip_len != len)
    {
        if(ip_len > len) 
        {
        	DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: -------------->  captured-len = %u, pkt-len = %u <-----------------\n",
					__FILE__, __LINE__, len, ip_len););
            ip_len = len;
            //return NF_DROP;
        }
    }

    if(ip_len < hlen)
    {
        p->iph = NULL;
		DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: too short, pkt-len = %u, hdr-len = %u\n",
				__FILE__, __LINE__, ip_len, hlen););
        return NF_DROP;
    }


    /* routers drop packets with bad IP checksums, we don't really 
     * need to check them (should make this a command line/config
     * option
     */
     if(!(p->csum_flags & CSE_IP)) {
        csum = in_chksum_ip((u_short *)p->iph, hlen);
        if(csum)
        {
            p->csum_flags |= CSE_IP;
    		DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: bad csum\n",
    				__FILE__, __LINE__););
            return NF_DROP;
        }
    }

    /* test for IP options */
    p->ip_options_len = hlen - IP_HEADER_LEN;

    if(p->ip_options_len > 0)//如果IP头部大于20字节
    {
        p->ip_options_data = pkt + IP_HEADER_LEN;
        if(NF_ACCEPT != DecodeIPOptions((pkt + IP_HEADER_LEN), p->ip_options_len, p)) {
		DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: bad ip options\n",
					__FILE__, __LINE__););
        	return NF_DROP;
	}
    }
    else
    {
        p->ip_option_count = 0;
    }

    /* set the real IP length for logging */
    p->actual_ip_len = (u_int16_t) ip_len;

    /* set the remaining packet length */
    ip_len -= hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->iph->ip_off);//前面 p->iph = (IPHdr *) pkt;

    /* 
     * get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    p->rf = (u_int8_t)((p->frag_offset & 0x8000) >> 15);
    p->df = (u_int8_t)((p->frag_offset & 0x4000) >> 14);
    p->mf = (u_int8_t)((p->frag_offset & 0x2000) >> 13);

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if(p->frag_offset || p->mf)
    {
        /* set the packet fragment flag */
        p->frag_flag = 1;
		DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: ip frag\n",
				__FILE__, __LINE__););
        return NF_STOLEN;
    }

    DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: IP decode OK\n",
			__FILE__, __LINE__);)

    if(p->iph->ip_proto == IPPROTO_TCP)
        return DecodeTCP(pkt + hlen, ip_len, p);

	 if(p->iph->ip_proto == IPPROTO_UDP)
        return DecodeUDP(pkt + hlen, ip_len, p);

	 if(p->iph->ip_proto == IPPROTO_ICMP)
        return DecodeICMP(pkt + hlen, ip_len, p);

 	 return NF_ACCEPT;
}
EXPORT_SYMBOL_GPL(DecodeIP);

/*
 * Function: DecodeTCP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the TCP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => Pointer to packet decode struct
 *
 * Returns: void function
 */
unsigned int DecodeTCP(u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    struct pseudoheader       /* pseudo header for TCP checksum calculations */
    {
        u_int32_t sip, dip;   /* IP addr */
        u_int8_t  zero;       /* checksum placeholder */
        u_int8_t  protocol;   /* protocol number */
        u_int16_t tcplen;     /* tcp packet length */
    };
    u_int32_t hlen;            /* TCP header length */
    u_short csum;              /* checksum */
    struct pseudoheader ph;    /* pseudo header declaration */

    if(len < 20)
    {
        p->tcph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeTCP too short: datalen=%u !!!\n",
				__FILE__, __LINE__, len););
        return NF_DROP;
    }

    /* lay TCP on top of the data cause there is enough of it! */
    p->tcph = (TCPHdr *) pkt;

    /* multiply the payload offset value by 4 */
    hlen = TCP_OFFSET(p->tcph) << 2;

    if(hlen < 20)
    {
        p->tcph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeTCP tcpheaderlen error: hlen=%u !!!\n",
				__FILE__, __LINE__, hlen););
        return NF_DROP;
    }

    if(hlen > len)
    {
        p->tcph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeTCP too short: hdlen=%u, datalen=%u !!!\n",
				__FILE__, __LINE__, hlen, len););
        return NF_DROP;
    }

    /* stuff more data into the printout data struct */
    p->sp = ntohs(p->tcph->th_sport);
    p->dp = ntohs(p->tcph->th_dport);


    /* setup the pseudo header for checksum calculation */
    ph.sip = p->iph->ip_src;
    ph.dip = p->iph->ip_dst;
    ph.zero = 0;
    ph.protocol = p->iph->ip_proto;
    ph.tcplen = htons((u_short)len);

#if 0
	{
    	unsigned short org = p->tcph->th_sum;

    	p->tcph->th_sum = 0;
    	p->tcph->th_sum = in_chksum_tcp((u_int16_t *)&ph, (u_int16_t *)(p->tcph), len);
	    DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: DecodeTCP: csum=%04x, %04x, len=%u, sip=%08x, dip=%08x\n",
				__FILE__, __LINE__, org, p->tcph->th_sum, len, ph.sip, ph.dip););
		p->tcph->th_sum = org;
	}
#endif
    /* if we're being "stateless" we probably don't care about the TCP 
     * checksum, but it's not bad to keep around for shits and giggles */
    /* calculate the checksum */
    if(!(p->csum_flags & CSE_TCP)) {
	    csum = in_chksum_tcp((u_int16_t *)&ph, (u_int16_t *)(p->tcph), len);
	    if(csum)
	    {
	        p->csum_flags |= CSE_TCP;
	        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeTCP checksum error !!!\n",
					__FILE__, __LINE__););
	        return NF_DROP;
	    }
    }

    /* if options are present, decode them */
    p->tcp_options_len = hlen - 20;
    
    if(p->tcp_options_len > 0)
    {
        p->tcp_options_data = pkt + 20;
		if(NF_ACCEPT != DecodeTCPOptions((u_int8_t *) (pkt + 20), p->tcp_options_len, p)) {
			DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeTCPOptions error !!!\n",
					__FILE__, __LINE__););
			return NF_DROP;
		}
    }
    else
    {
        p->tcp_option_count = 0;
    }

    /* set the data pointer and size */
    p->data = (u_int8_t *) (pkt + hlen);

    if(hlen < len)
    {
        p->dsize = (u_short)(len - hlen);
    }
    else
    {
        p->dsize = 0;
    }

    DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: DecodeTCP OK, dsize = %u.\n",
			__FILE__, __LINE__, p->dsize););

    return NF_ACCEPT;
}


/*
 * Function: DecodeUDP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the UDP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to decoded packet struct  
 *
 * Returns: void function
 */
unsigned int DecodeUDP(u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    struct pseudoheader 
    {
        u_int32_t sip, dip;
        u_int8_t  zero;
        u_int8_t  protocol;
        u_int16_t udplen;
    };
    u_short csum;
    u_int16_t uhlen;
    struct pseudoheader ph;

    if(len < sizeof(UDPHdr))
    {
        p->udph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeUDP error: datalen=%u < sizeof(UDPHdr)=%u !!!\n",
				__FILE__, __LINE__, len, sizeof(UDPHdr)););
        return NF_DROP;
    }

    /* set the ptr to the start of the UDP header */
    p->udph = (UDPHdr *) pkt;

    if (!p->frag_flag)
    {
        uhlen = ntohs(p->udph->uh_len);
    }
    else
    {
#if 0
        u_int16_t ip_len = ntohs(p->iph->ip_len);
        /* Don't forget, IP_HLEN is a word - multiply x 4 */
        uhlen = ip_len - (IP_HLEN(p->iph) * 4 );
#else
        p->udph->uh_chk = 0;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeUDP error: rcv frag !!!\n",
				__FILE__, __LINE__););
		return NF_DROP;
#endif
    }
    
    /* verify that the header len is a valid value */
    if(uhlen < UDP_HEADER_LEN)
    {
        p->udph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeUDP error: uhlen=%u < %u !!!\n",
				__FILE__, __LINE__, uhlen, UDP_HEADER_LEN););
        return NF_DROP;
    }

    /* make sure there are enough bytes as designated by length field */
    if(len < uhlen)
    {
        p->udph = NULL;
         DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeUDP error: datalen=%u < uhlen=%u !!!\n",
				__FILE__, __LINE__, len, uhlen););
        return NF_DROP;
    }

    /* fill in the printout data structs */
    p->sp = ntohs(p->udph->uh_sport);
    p->dp = ntohs(p->udph->uh_dport);

    /* look at the UDP checksum to make sure we've got a good packet */
    ph.sip = p->iph->ip_src;
    ph.dip = p->iph->ip_dst;
    ph.zero = 0;
    ph.protocol = p->iph->ip_proto;
    ph.udplen = p->udph->uh_len; 

    if(!(p->csum_flags & CSE_UDP)) {
    if(p->udph->uh_chk)
    {
        csum = in_chksum_udp((u_int16_t *)&ph, (u_int16_t *)(p->udph), uhlen);
    }
    else
    {
        csum = 0;
    }
    if(csum)
    {
        p->csum_flags |= CSE_UDP;
         DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeUDP error: checksum !!!\n",
				__FILE__, __LINE__););
        return NF_DROP;
    }
    }

    DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: DecodeUDP OK\n",
				__FILE__, __LINE__););

    p->data = (u_int8_t *) (pkt + UDP_HEADER_LEN);
    
    /* length was validated up above */
    p->dsize = uhlen - UDP_HEADER_LEN; 

    return NF_ACCEPT;
}


/*
 * Function: DecodeIPOnly(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the IP network layer but not recurse
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to dummy packet decode struct
 *
 * Returns: void function
 */
int DecodeIPOnly(u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    u_int32_t ip_len;       /* length from the start of the ip hdr to the
                             * pkt end */
    u_int32_t hlen;             /* ip header length */

    /* lay the IP struct over the raw data */
    p->orig_iph = (IPHdr *) pkt;

    //DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "DecodeIPOnly: ip header starts at: %p, "
    //            "length is %lu\n", p->orig_iph, (unsigned long) len););

    /* do a little validation */
    if(len < IP_HEADER_LEN)
    {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeIPOnly error: ICMP Unreachable IP short header (%d bytes)\n",
			__FILE__, __LINE__, len););
        p->orig_iph = NULL;
        return(0);
    }

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if(IP_VER(p->orig_iph) != 4)
    {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeIPOnly error: ICMP Unreachable not IPv4 datagram ([ver: 0x%x][len: 0x%x])\n",
			__FILE__, __LINE__, IP_VER(p->orig_iph), p->orig_iph->ip_len););
        p->orig_iph = NULL;
        return(0);
    }

    /* set the IP datagram length */
    ip_len = ntohs(p->orig_iph->ip_len);

    /* set the IP header length */
    hlen = IP_HLEN(p->orig_iph) << 2;

    if(len < hlen)
    {
    	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeIPOnly error: ICMP Unreachable IP len (%d bytes) < IP hdr len (%d bytes), packet discarded\n",
			__FILE__, __LINE__, ip_len, hlen););
        p->orig_iph = NULL;
        return(0);
    }

    p->ip_option_count = 0;

    /* set the remaining packet length */
    ip_len = len - hlen;

    /* check for fragmented packets */
    p->frag_offset = ntohs(p->orig_iph->ip_off);

    /* get the values of the reserved, more 
     * fragments and don't fragment flags 
     */
    p->rf = (u_int8_t)(p->frag_offset & 0x8000) >> 15;
    p->df = (u_int8_t)(p->frag_offset & 0x4000) >> 14;
    p->mf = (u_int8_t)(p->frag_offset & 0x2000) >> 13;

    /* mask off the high bits in the fragment offset field */
    p->frag_offset &= 0x1FFF;

    if(p->frag_offset || p->mf)
    {
        /* set the packet fragment flag */
        p->frag_flag = 1;

        /* set the payload pointer and payload size */
        p->data = pkt + hlen;
        p->dsize = (u_short) ip_len;
    }
    else
    {
        p->frag_flag = 0;

		DECODE_DBG(printk(KERN_DEBUG "<%s, %d>: DecodeIPOnly: ICMP Unreachable IP header length: %lu\n",
			__FILE__, __LINE__, (unsigned long)hlen););

        switch(p->orig_iph->ip_proto)
        {
            case IPPROTO_TCP: /* decode the interesting part of the header */
                if(ip_len > 4)
                {
                    p->orig_tcph =(TCPHdr *)(pkt + hlen);

                    /* stuff more data into the printout data struct */
                    p->orig_sp = ntohs(p->orig_tcph->th_sport);
                    p->orig_dp = ntohs(p->orig_tcph->th_dport);
                }

                break;

            case IPPROTO_UDP:
                if(ip_len > 4)
                {
                    p->orig_udph = (UDPHdr *)(pkt + hlen);

                    /* fill in the printout data structs */
                    p->orig_sp = ntohs(p->orig_udph->uh_sport);
                    p->orig_dp = ntohs(p->orig_udph->uh_dport);
                }

                break;

            case IPPROTO_ICMP:
                if(ip_len > 4)
                {
                    p->orig_icmph = (ICMPHdr *) (pkt+hlen);
                }

                break;
        }
    }

    return(1);
}


/*
 * Function: DecodeICMP(u_int8_t *, const u_int32_t, Packet *)
 *
 * Purpose: Decode the ICMP transport layer
 *
 * Arguments: pkt => ptr to the packet data
 *            len => length from here to the end of the packet
 *            p   => pointer to the decoded packet struct
 *
 * Returns: void function
 */
unsigned int DecodeICMP(u_int8_t * pkt, const u_int32_t len, Packet * p)
{
    u_int16_t csum;
    u_int32_t orig_p_caplen;

    if(len < ICMP_HEADER_LEN)
    {
        p->udph = NULL;
        DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: datalen=%u < sizeof(UDPHdr)=%u !!!\n",
				__FILE__, __LINE__, len, sizeof(UDPHdr)););
        return NF_DROP;
    }

    /* set the header ptr first */
    p->icmph = (ICMPHdr *) pkt;

    switch (p->icmph->type)
    {
        case ICMP_ECHOREPLY:
        case ICMP_DEST_UNREACH:
        case ICMP_SOURCE_QUENCH:
        case ICMP_REDIRECT:
        case ICMP_ECHO:
        case ICMP_ROUTER_ADVERTISE:
        case ICMP_ROUTER_SOLICIT:
        case ICMP_TIME_EXCEEDED:
        case ICMP_PARAMETERPROB:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            if (len < 8)
            {
				p->udph = NULL;
				DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: Truncated ICMP header(%d bytes)\n",
					__FILE__, __LINE__, len););
				return NF_DROP;
            }
            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            if (len < 20)
            {
                p->udph = NULL;
				DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: Truncated ICMP header(%d bytes)\n",
					__FILE__, __LINE__, len););
				return NF_DROP;
            }
            break;

        case ICMP_ADDRESS:
        case ICMP_ADDRESSREPLY:
            if (len < 12)
            {
                p->udph = NULL;
				DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: Truncated ICMP header(%d bytes)\n",
					__FILE__, __LINE__, len););
				return NF_DROP;
            }
            break;
    }


    if(!(p->csum_flags & CSE_ICMP)) {
	csum = in_chksum_icmp((u_int16_t *)p->icmph, len);
	if(csum)
	{
		p->csum_flags |= CSE_ICMP;
		DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: checksum !!!\n",
				__FILE__, __LINE__););
        return NF_DROP;
	}
	}

    p->dsize = (u_short)(len - ICMP_HEADER_LEN);
    p->data = pkt + ICMP_HEADER_LEN;

    //DEBUG_WRAP(DebugMessage(DEBUG_DECODE, "ICMP type: %d   code: %d\n", 
    //            p->icmph->code, p->icmph->type););

    switch(p->icmph->type)
    {
        case ICMP_ECHOREPLY:
            /* setup the pkt id ans seq numbers */
            p->dsize -= sizeof(struct idseq);
            p->data += sizeof(struct idseq);
            break;

        case ICMP_ECHO:
            /* setup the pkt id and seq numbers */
            p->dsize -= sizeof(struct idseq);   /* add the size of the 
                                                 * echo ext to the data
                                                 * ptr and subtract it 
                                                 * from the data size */
            p->data += sizeof(struct idseq);
            break;

        case ICMP_DEST_UNREACH:
            {
                /* if unreach packet is smaller than expected! */
                if(len < 16)
                {
                	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: Truncated ICMP-UNREACH header(%d bytes)\n",
						__FILE__, __LINE__, len););

                    /* if it is less than 8 we are in trouble */
                    if(len < 8)
                        break;
                }

                orig_p_caplen = len - 8;

                if(!DecodeIPOnly(pkt + 8, orig_p_caplen, p))
            	{
            		return NF_DROP;
            	}
            }

            break;

        case ICMP_REDIRECT:
            {
                /* if unreach packet is smaller than expected! */
                if(p->dsize < 28)
                {
                	DECODE_WARN(printk(KERN_DEBUG "<%s, %d>: DecodeICMP error: Truncated ICMP-REDIRECT header(%d bytes)\n",
						__FILE__, __LINE__, len););
                        
                    /* if it is less than 8 we are in trouble */
                    if(p->dsize < 8)
                        break;
                }

                orig_p_caplen = p->dsize - 8;

                if(!DecodeIPOnly(pkt + 8, orig_p_caplen, p))
                {
                	return NF_DROP;
                }
            }

            break;
    }

	/* zjy: icmp type and code, put in sp and dp */
	p->sp = p->icmph->type;
    p->dp = p->icmph->code;

	return NF_ACCEPT;
}



/** 
 * Validate that the length is an expected length AND that it's in bounds
 *
 * EOL and NOP are handled separately
 * 
 * @param option_ptr current location
 * @param end the byte past the end of the decode list
 * @param len_ptr the pointer to the length field
 * @param expected_len the number of bytes we expect to see per rfc KIND+LEN+DATA, -1 means dynamic.
 * @param tcpopt options structure to populate
 * @param byte_skip distance to move upon completion
 *
 * @return returns 0 on success, < 0 on error
 */
static inline int OptLenValidate(u_int8_t *option_ptr,
                                    u_int8_t *end,
                                    u_int8_t *len_ptr,
                                    int expected_len,
                                    Options *tcpopt,
                                    u_int8_t *byte_skip)
{
    *byte_skip = 0;
    
    if(len_ptr == NULL)
    {
        return TCP_OPT_TRUNC;
    }
    
    if(len_ptr == 0 || expected_len == 0 || expected_len == 1)
    {
        return TCP_OPT_BADLEN;
    }
    else if(expected_len > 1)
    {
        if((option_ptr + expected_len) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }

        if(*len_ptr != expected_len)
        {
            /* length is not valid */
            return TCP_OPT_BADLEN;
        }
    }
    else /* expected_len < 0 (i.e. variable length) */
    {
        if(*len_ptr < 2)
        {
            /* RFC sez that we MUST have atleast this much data */
            return TCP_OPT_BADLEN;
        }
           
        if((option_ptr + *len_ptr) > end)
        {
            /* not enough data to read in a perfect world */
            return TCP_OPT_TRUNC;
        }
    }

    tcpopt->len = *len_ptr - 2;

    if(*len_ptr == 2)
    {
        tcpopt->data = NULL;
    }
    else
    {
        tcpopt->data = option_ptr + 2;
    }

    *byte_skip = *len_ptr;
    
    return 0;
}

/*
 * Function: DecodeTCPOptions(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Fairly self explainatory name, don't you think?
 *
 *          TCP Option Header length validation is left to the caller
 *
 *          For a good listing of TCP Options, 
 *          http://www.iana.org/assignments/tcp-parameters 
 *
 *   ------------------------------------------------------------
 *   From: "Kastenholz, Frank" <FKastenholz@unispherenetworks.com>
 *   Subject: Re: skeeter & bubba TCP options?
 *
 *   ah, the sins of ones youth that never seem to be lost...
 *
 *   it was something that ben levy and stev and i did at ftp many
 *   many moons ago. bridgham and stev were the instigators of it.
 *   the idea was simple, put a dh key exchange directly in tcp
 *   so that all tcp sessions could be encrypted without requiring
 *   any significant key management system. authentication was not
 *   a part of the idea, it was to be provided by passwords or
 *   whatever, which could now be transmitted over the internet
 *   with impunity since they were encrypted... we implemented
 *   a simple form of this (doing the math was non trivial on the
 *   machines of the day). it worked. the only failure that i 
 *   remember was that it was vulnerable to man-in-the-middle 
 *   attacks.
 *   
 *   why "skeeter" and "bubba"? well, that's known only to stev...
 *   ------------------------------------------------------------
 *
 * 4.2.2.5 TCP Options: RFC-793 Section 3.1
 *
 *    A TCP MUST be able to receive a TCP option in any segment. A TCP
 *    MUST ignore without error any TCP option it does not implement,
 *    assuming that the option has a length field (all TCP options
 *    defined in the future will have length fields). TCP MUST be
 *    prepared to handle an illegal option length (e.g., zero) without
 *    crashing; a suggested procedure is to reset the connection and log
 *    the reason.
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
unsigned int DecodeTCPOptions(u_int8_t *start, u_int32_t o_len, Packet *p)
{
    u_int8_t *option_ptr = start;
    u_int8_t *end_ptr = start + o_len; /* points to byte after last option */
    u_int8_t *len_ptr;
    u_int32_t opt_count = 0;
    u_char done = 0; /* have we reached TCPOPT_EOL yet?*/
    u_char experimental_option_found = 0;      /* are all options RFC compliant? */
    u_char obsolete_option_found = 0;
    u_char ttcp_found = 0;
    
    int code = 2;
    u_int8_t byte_skip;

    /* Here's what we're doing so that when we find out what these
     * other buggers of TCP option codes are, we can do something
     * useful
     * 
     * 1) get option code
     * 2) check for enough space for current option code
     * 3) set option data ptr
     * 4) increment option code ptr
     *
     * TCP_OPTLENMAX = 40 because of
     *        (((2^4) - 1) * 4  - TCP_HEADER_LEN)
     *      
     */

    if(o_len > TCP_OPTLENMAX)
    {
        /* This shouldn't ever alert if we are doing our job properly
         * in the caller */        
        p->tcph = NULL; /* let's just alert */
        return NF_DROP;
    }
    
    while((option_ptr < end_ptr) && (opt_count < TCP_OPTLENMAX) && (code >= 0) && !done)
    {
        p->tcp_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }
        
        switch(*option_ptr)
        {
        case TCPOPT_EOL:
            done = 1; /* fall through to the NOP case */
        case TCPOPT_NOP:
            p->tcp_options[opt_count].len = 0; 
            p->tcp_options[opt_count].data = NULL;
            byte_skip = 1;
            code = 0;
            break;
        case TCPOPT_MAXSEG:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MAXSEG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_SACKOK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_SACKOK,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_WSCALE:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_WSCALE,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;            
        case TCPOPT_ECHO: /* both use the same lengths */
        case TCPOPT_ECHOREPLY:
            obsolete_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_ECHO,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_MD5SIG:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_MD5SIG,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_SACK:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            if(p->tcp_options[opt_count].data == NULL)
                code = TCP_OPT_BADLEN;

            break;
        case TCPOPT_CC_ECHO:
            ttcp_found = 1;
            /* fall through */
        case TCPOPT_CC:  /* all 3 use the same lengths / T/TCP */
        case TCPOPT_CC_NEW:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_CC,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        case TCPOPT_TRAILER_CSUM:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TRAILER_CSUM,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;

        case TCPOPT_TIMESTAMP:
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, TCPOLEN_TIMESTAMP,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
    
        case TCPOPT_SKEETER:
        case TCPOPT_BUBBA:
        case TCPOPT_UNASSIGNED:
            obsolete_option_found = 1;
        default:
        case TCPOPT_SCPS:  
        case TCPOPT_SELNEGACK:
        case TCPOPT_RECORDBOUND:
        case TCPOPT_CORRUPTION:
        case TCPOPT_PARTIAL_PERM:
        case TCPOPT_PARTIAL_SVC:
        case TCPOPT_ALTCSUM:
        case TCPOPT_SNAP:
            experimental_option_found = 1;
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->tcp_options[opt_count], &byte_skip);
            break;
        }

        if(code < 0)
        {
            return NF_DROP;
        }

        opt_count++;

        option_ptr += byte_skip;
    }

    p->tcp_option_count = opt_count;

    if(obsolete_option_found)
    	return NF_DROP;

    return NF_ACCEPT;
}


/*
 * Function: DecodeIPOptions(u_int8_t *, u_int32_t, Packet *)
 *
 * Purpose: Once again, a fairly self-explainatory name
 *
 * Arguments: o_list => ptr to the option list
 *            o_len => length of the option list
 *            p     => pointer to decoded packet struct
 *
 * Returns: void function
 */
unsigned int DecodeIPOptions(u_int8_t *start, u_int32_t o_len, Packet *p)
{
    u_int8_t *option_ptr = start;
    u_char done = 0; /* have we reached IP_OPTEOL yet? */
    u_int8_t *end_ptr = start + o_len;
    u_int32_t opt_count = 0; /* what option are we processing right now */
    u_int8_t byte_skip;
    u_int8_t *len_ptr;
    int code = 0;  /* negative error codes are returned from bad options */
    
    while((option_ptr < end_ptr) && (opt_count < IP_OPTMAX) && (code >= 0))
    {
        p->ip_options[opt_count].code = *option_ptr;

        if((option_ptr + 1) < end_ptr)
        {
            len_ptr = option_ptr + 1;
        }
        else
        {
            len_ptr = NULL;
        }

        switch(*option_ptr)
        {
        case IPOPT_RTRALT:
        case IPOPT_NOP:
        case IPOPT_EOL:
            /* if we hit an EOL, we're done */
            if(*option_ptr == IPOPT_EOL)
                done = 1;
            
            p->ip_options[opt_count].len = 0;
            p->ip_options[opt_count].data = NULL;
            byte_skip = 1;
            break;
        default:
            /* handle all the dynamic features */
            code = OptLenValidate(option_ptr, end_ptr, len_ptr, -1,
                                  &p->ip_options[opt_count], &byte_skip);
        }

        if(code < 0)
        {
            return NF_DROP;
        }

        if(!done)
            opt_count++;

        option_ptr += byte_skip;
    }
    
    p->ip_option_count = opt_count;

    return NF_ACCEPT;
}

MODULE_LICENSE("GPL");


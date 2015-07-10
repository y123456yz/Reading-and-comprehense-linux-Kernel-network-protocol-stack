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

/* $Id: decode.h,v 1.2 2010/05/14 07:46:05 cailiyang Exp $ */


#ifndef __DECODE_H__
#define __DECODE_H__


/*  I N C L U D E S  **********************************************************/

#include <linux/types.h>
#include <linux/kernel.h>

//#include "stream.h"
#include "pintercept.h"

/*
static inline int InlineMode(void)
{
	return 1;
}
*/

void _InlineDrop_(void);
void _InlineSkip_(void);

#define InlineDrop() do { \
	_InlineDrop_(); \
} while(0)

#define InlineSkip() do { \
	_InlineSkip_(); \
} while(0)

/*  D E F I N E S  ************************************************************/
#define ETHERNET_MTU                  1500
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000

#define ETH_DSAP_SNA                  0x08    /* SNA */
#define ETH_SSAP_SNA                  0x00    /* SNA */
#define ETH_DSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_SSAP_STP                  0x42    /* Spanning Tree Protocol */
#define ETH_DSAP_IP                   0xaa    /* IP */
#define ETH_SSAP_IP                   0xaa    /* IP */

#define ETH_ORG_CODE_ETHR              0x000000    /* Encapsulated Ethernet */
#define ETH_ORG_CODE_CDP               0x00000c    /* Cisco Discovery Proto */

#define ETHERNET_HEADER_LEN             14
#define ETHERNET_MAX_LEN_ENCAP          1518    /* 802.3 (+LLC) or ether II ? */
#define PPPOE_HEADER_LEN                20    /* ETHERNET_HEADER_LEN + 6 */
#define MINIMAL_TOKENRING_HEADER_LEN    22
#define MINIMAL_IEEE80211_HEADER_LEN    10    /* Ack frames and others */
#define IEEE802_11_DATA_HDR_LEN         24    /* Header for data packets */
#define TR_HLEN                         MINIMAL_TOKENRING_HEADER_LEN
#define TOKENRING_LLC_LEN                8
#define SLIP_HEADER_LEN                 16

/* Frame type/subype combinations with version = 0 */
        /*** FRAME TYPE *****  HEX ****  SUBTYPE TYPE  DESCRIPT ********/
#define WLAN_TYPE_MGMT_ASREQ   0x0      /* 0000    00  Association Req */
#define WLAN_TYPE_MGMT_ASRES   0x10     /* 0001    00  Assocaition Res */
#define WLAN_TYPE_MGMT_REREQ   0x20     /* 0010    00  Reassoc. Req.   */
#define WLAN_TYPE_MGMT_RERES   0x30     /* 0011    00  Reassoc. Resp.  */
#define WLAN_TYPE_MGMT_PRREQ   0x40     /* 0100    00  Probe Request   */
#define WLAN_TYPE_MGMT_PRRES   0x50     /* 0101    00  Probe Response  */ 
#define WLAN_TYPE_MGMT_BEACON  0x80     /* 1000    00  Beacon          */
#define WLAN_TYPE_MGMT_ATIM    0x90     /* 1001    00  ATIM message    */
#define WLAN_TYPE_MGMT_DIS     0xa0     /* 1010    00  Disassociation  */
#define WLAN_TYPE_MGMT_AUTH    0xb0     /* 1011    00  Authentication  */
#define WLAN_TYPE_MGMT_DEAUTH  0xc0     /* 1100    00  Deauthentication*/

#define WLAN_TYPE_CONT_PS      0xa4     /* 1010    01  Power Save      */
#define WLAN_TYPE_CONT_RTS     0xb4     /* 1011    01  Request to send */
#define WLAN_TYPE_CONT_CTS     0xc4     /* 1100    01  Clear to sene   */
#define WLAN_TYPE_CONT_ACK     0xd4     /* 1101    01  Acknowledgement */
#define WLAN_TYPE_CONT_CFE     0xe4     /* 1110    01  Cont. Free end  */
#define WLAN_TYPE_CONT_CFACK   0xf4     /* 1111    01  CF-End + CF-Ack */

#define WLAN_TYPE_DATA_DATA    0x08     /* 0000    10  Data            */
#define WLAN_TYPE_DATA_DTCFACK 0x18     /* 0001    10  Data + CF-Ack   */
#define WLAN_TYPE_DATA_DTCFPL  0x28     /* 0010    10  Data + CF-Poll  */
#define WLAN_TYPE_DATA_DTACKPL 0x38     /* 0011    10  Data+CF-Ack+CF-Pl */
#define WLAN_TYPE_DATA_NULL    0x48     /* 0100    10  Null (no data)  */
#define WLAN_TYPE_DATA_CFACK   0x58     /* 0101    10  CF-Ack (no data)*/
#define WLAN_TYPE_DATA_CFPL    0x68     /* 0110    10  CF-Poll (no data)*/
#define WLAN_TYPE_DATA_ACKPL   0x78     /* 0111    10  CF-Ack+CF-Poll  */

/*** Flags for IEEE 802.11 Frame Control ***/
/* The following are designed to be bitwise-AND-d in an 8-bit u_char */
#define WLAN_FLAG_TODS      0x0100    /* To DS Flag   10000000 */
#define WLAN_FLAG_FROMDS    0x0200    /* From DS Flag 01000000 */
#define WLAN_FLAG_FRAG      0x0400    /* More Frag    00100000 */
#define WLAN_FLAG_RETRY     0x0800    /* Retry Flag   00010000 */
#define WLAN_FLAG_PWRMGMT   0x1000    /* Power Mgmt.  00001000 */
#define WLAN_FLAG_MOREDAT   0x2000    /* More Data    00000100 */
#define WLAN_FLAG_WEP       0x4000    /* Wep Enabled  00000010 */
#define WLAN_FLAG_ORDER     0x8000    /* Strict Order 00000001 */

/* IEEE 802.1x eapol types */
#define EAPOL_TYPE_EAP      0x00      /* EAP packet */
#define EAPOL_TYPE_START    0x01      /* EAPOL start */
#define EAPOL_TYPE_LOGOFF   0x02      /* EAPOL Logoff */
#define EAPOL_TYPE_KEY      0x03      /* EAPOL Key */
#define EAPOL_TYPE_ASF      0x04      /* EAPOL Encapsulated ASF-Alert */

/* Extensible Authentication Protocol Codes RFC 2284*/
#define EAP_CODE_REQUEST    0x01   
#define EAP_CODE_RESPONSE   0x02
#define EAP_CODE_SUCCESS    0x03
#define EAP_CODE_FAILURE    0x04
/* EAP Types */
#define EAP_TYPE_IDENTITY   0x01
#define EAP_TYPE_NOTIFY     0x02
#define EAP_TYPE_NAK        0x03
#define EAP_TYPE_MD5        0x04
#define EAP_TYPE_OTP        0x05
#define EAP_TYPE_GTC        0x06
#define EAP_TYPE_TLS        0x0d

/* otherwise defined in /usr/include/ppp_defs.h */
#define IP_HEADER_LEN           20
#define TCP_HEADER_LEN          20
#define UDP_HEADER_LEN          8
#define ICMP_HEADER_LEN         4

#define IP_OPTMAX               40
#define TCP_OPTLENMAX           40 /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */

#ifndef IP_MAXPACKET
#define IP_MAXPACKET    65535        /* maximum packet size */
#endif /* IP_MAXPACKET */

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_RES2 0x40
#define TH_RES1 0x80
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

/* http://www.iana.org/assignments/tcp-parameters
 *
 * tcp options stuff. used to be in <netinet/tcp.h> but it breaks
 * things on AIX
 */
#define TCPOPT_EOL              0   /* End of Option List [RFC793] */
#define TCPOLEN_EOL             1   /* Always one byte */

#define TCPOPT_NOP              1   /* No-Option [RFC793] */
#define TCPOLEN_NOP             1   /* Always one byte */

#define TCPOPT_MAXSEG           2   /* Maximum Segment Size [RFC793] */
#define TCPOLEN_MAXSEG          4   /* Always 4 bytes */

#define TCPOPT_WSCALE           3   /* Window scaling option [RFC1323] */
#define TCPOLEN_WSCALE          3   /* 1 byte with logarithmic values */

#define TCPOPT_SACKOK           4    /* Experimental [RFC2018]*/
#define TCPOLEN_SACKOK          2

#define TCPOPT_SACK             5    /* Experimental [RFC2018] variable length */

#define TCPOPT_ECHO             6    /* Echo (obsoleted by option 8)      [RFC1072] */
#define TCPOLEN_ECHO            6    /* 6 bytes  */

#define TCPOPT_ECHOREPLY        7    /* Echo Reply (obsoleted by option 8)[RFC1072] */
#define TCPOLEN_ECHOREPLY       6    /* 6 bytes  */

#define TCPOPT_TIMESTAMP        8   /* Timestamp [RFC1323], 10 bytes */
#define TCPOLEN_TIMESTAMP       10

#define TCPOPT_PARTIAL_PERM     9   /* Partial Order Permitted/ Experimental [RFC1693] */
#define TCPOLEN_PARTIAL_PERM    2   /* Partial Order Permitted/ Experimental [RFC1693] */

#define TCPOPT_PARTIAL_SVC      10  /*  Partial Order Profile [RFC1693] */
#define TCPOLEN_PARTIAL_SVC     3   /*  3 bytes long -- Experimental */

/* atleast decode T/TCP options... */
#define TCPOPT_CC               11  /*  T/TCP Connection count  [RFC1644] */
#define TCPOPT_CC_NEW           12  /*  CC.NEW [RFC1644] */
#define TCPOPT_CC_ECHO          13  /*  CC.ECHO [RFC1644] */
#define TCPOLEN_CC             6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_NEW         6  /* page 17 of rfc1644 */
#define TCPOLEN_CC_ECHO        6  /* page 17 of rfc1644 */

#define TCPOPT_ALTCSUM          15  /* TCP Alternate Checksum Data [RFC1146], variable length */
#define TCPOPT_SKEETER          16  /* Skeeter [Knowles] */
#define TCPOPT_BUBBA            17  /* Bubba   [Knowles] */

#define TCPOPT_TRAILER_CSUM     18  /* Trailer Checksum Option [Subbu & Monroe] */
#define TCPOLEN_TRAILER_CSUM  3  

#define TCPOPT_MD5SIG           19  /* MD5 Signature Option [RFC2385] */
#define TCPOLEN_MD5SIG        18

/* Space Communications Protocol Standardization */
#define TCPOPT_SCPS             20  /* Capabilities [Scott] */
#define TCPOPT_SELNEGACK        21  /* Selective Negative Acknowledgements [Scott] */
#define TCPOPT_RECORDBOUND         22  /* Record Boundaries [Scott] */
#define TCPOPT_CORRUPTION          23  /* Corruption experienced [Scott] */

#define TCPOPT_SNAP                24  /* SNAP [Sukonnik] -- anyone have info?*/
#define TCPOPT_UNASSIGNED          25  /* Unassigned (released 12/18/00) */
#define TCPOPT_COMPRESSION         26  /* TCP Compression Filter [Bellovin] */
/* http://www.research.att.com/~smb/papers/draft-bellovin-tcpcomp-00.txt*/

#define TCP_OPT_TRUNC -1
#define TCP_OPT_BADLEN -2

/* Why are these lil buggers here? Never Used. -- cmg */
#define TCPOLEN_TSTAMP_APPA     (TCPOLEN_TIMESTAMP+2)    /* appendix A / rfc 1323 */
#define TCPOPT_TSTAMP_HDR    \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

/*
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */

#ifndef TCP_MSS
    #define    TCP_MSS      512
#endif

#ifndef TCP_MAXWIN
    #define    TCP_MAXWIN   65535    /* largest value for (unscaled) window */
#endif

#ifndef TCP_MAX_WINSHIFT 
    #define TCP_MAX_WINSHIFT    14    /* maximum window shift */
#endif

/*
 * User-settable options (used with setsockopt).
 */
#ifndef TCP_NODELAY
    #define    TCP_NODELAY   0x01    /* don't delay send to coalesce packets */
#endif

#ifndef TCP_MAXSEG
    #define    TCP_MAXSEG    0x02    /* set maximum segment size */
#endif

#define SOL_TCP        6    /* TCP level */



#define L2TP_PORT           1701
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_PORT    67

/* IRIX 6.2 hack! */
#ifndef IRIX
    #define SNAPLEN         1514
#else
    #define SNAPLEN         1500
#endif

#define MIN_SNAPLEN         68
#define PROMISC             1
#define READ_TIMEOUT        500

#define ICMP_ECHOREPLY          0    /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4    /* Source Quench                */
#define ICMP_REDIRECT           5    /* Redirect (change route)      */
#define ICMP_ECHO               8    /* Echo Request                 */
#define ICMP_ROUTER_ADVERTISE   9    /* Router Advertisement         */
#define ICMP_ROUTER_SOLICIT     10    /* Router Solicitation          */
#define ICMP_TIME_EXCEEDED      11    /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12    /* Parameter Problem            */
#define ICMP_TIMESTAMP          13    /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14    /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15    /* Information Request          */
#define ICMP_INFO_REPLY         16    /* Information Reply            */
#define ICMP_ADDRESS            17    /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18    /* Address Mask Reply           */
#define NR_ICMP_TYPES           18

/* Codes for ICMP UNREACHABLES */
#define ICMP_NET_UNREACH        0    /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1    /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2    /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3    /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4    /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5    /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_PKT_FILTERED_NET   9
#define ICMP_PKT_FILTERED_HOST  10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13    /* Packet filtered */
#define ICMP_PREC_VIOLATION     14    /* Precedence violation */
#define ICMP_PREC_CUTOFF        15    /* Precedence cut off */
#define NR_ICMP_UNREACH         15    /* instead of hardcoding immediate
                                       * value */

#define ICMP_REDIR_NET          0
#define ICMP_REDIR_HOST         1
#define ICMP_REDIR_TOS_NET      2
#define ICMP_REDIR_TOS_HOST     3

#define ICMP_TIMEOUT_TRANSIT    0
#define ICMP_TIMEOUT_REASSY     1

#define ICMP_PARAM_BADIPHDR     0
#define ICMP_PARAM_OPTMISSING   1
#define ICMP_PARAM_BAD_LENGTH   2

/* ip option type codes */
#ifndef IPOPT_EOL
    #define IPOPT_EOL            0x00
#endif

#ifndef IPOPT_NOP
    #define IPOPT_NOP            0x01
#endif

#ifndef IPOPT_RR
    #define IPOPT_RR             0x07
#endif

#ifndef IPOPT_RTRALT
    #define IPOPT_RTRALT         0x14
#endif

#ifndef IPOPT_TS
    #define IPOPT_TS             0x44
#endif

#ifndef IPOPT_SECURITY
    #define IPOPT_SECURITY       0x82
#endif

#ifndef IPOPT_LSRR
    #define IPOPT_LSRR           0x83
#endif

#ifndef IPOPT_LSRR_E
    #define IPOPT_LSRR_E         0x84
#endif

#ifndef IPOPT_SATID
    #define IPOPT_SATID          0x88
#endif

#ifndef IPOPT_SSRR
    #define IPOPT_SSRR           0x89
#endif



/* tcp option codes */
#define TOPT_EOL                0x00
#define TOPT_NOP                0x01
#define TOPT_MSS                0x02
#define TOPT_WS                 0x03
#define TOPT_TS                 0x08
#ifndef TCPOPT_WSCALE
    #define TCPOPT_WSCALE           3     /* window scale factor (rfc1072) */
#endif
#ifndef TCPOPT_SACKOK
    #define    TCPOPT_SACKOK        4     /* selective ack ok (rfc1072) */
#endif
#ifndef TCPOPT_SACK
    #define    TCPOPT_SACK          5     /* selective ack (rfc1072) */
#endif
#ifndef TCPOPT_ECHO
    #define TCPOPT_ECHO             6     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_ECHOREPLY
    #define TCPOPT_ECHOREPLY        7     /* echo (rfc1072) */
#endif
#ifndef TCPOPT_TIMESTAMP
    #define TCPOPT_TIMESTAMP        8     /* timestamps (rfc1323) */
#endif
#ifndef TCPOPT_CC
    #define TCPOPT_CC               11    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCNEW
    #define TCPOPT_CCNEW            12    /* T/TCP CC options (rfc1644) */
#endif
#ifndef TCPOPT_CCECHO
    #define TCPOPT_CCECHO           13    /* T/TCP CC options (rfc1644) */
#endif

#define EXTRACT_16BITS(p) ((u_short) ntohs (*(u_short *)(p)))

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
    #define EXTRACT_32BITS(p)  ({ u_int32_t __tmp; memmove(&__tmp, (p), sizeof(u_int32_t)); (u_int32_t) ntohl(__tmp);})
#endif /* __GNUC__ */

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
    #define EXTRACT_32BITS(p) ((u_int32_t) ntohl (*(u_int32_t *)(p)))

#endif                /* WORDS_MUSTALIGN */

/* packet status flags */
#define PKT_REBUILT_FRAG     0x00000001  /* is a rebuilt fragment */
#define PKT_REBUILT_STREAM   0x00000002  /* is a rebuilt stream */
#define PKT_STREAM_UNEST_UNI 0x00000004  /* is from an unestablished stream and
                                          * we've only seen traffic in one
                                          * direction
                                          */
#define PKT_STREAM_UNEST_BI  0x00000008  /* is from an unestablished stream and
                                          * we've seen traffic in both 
                                          * directions
                                          */
#define PKT_STREAM_EST       0x00000010  /* is from an established stream */
#define PKT_ECN              0x00000020  /* this is ECN traffic */
#define PKT_FROM_SERVER      0x00000040  /* this packet came from the server
                                            side of a connection (TCP) */
#define PKT_FROM_CLIENT      0x00000080  /* this packet came from the client
                                            side of a connection (TCP) */
#define PKT_HTTP_DECODE      0x00000100  /* this packet has normalized http */
#define PKT_FRAG_ALERTED     0x00000200  /* this packet has been alerted by 
                                            defrag */
#define PKT_STREAM_INSERT    0x00000400  /* this packet has been inserted into stream4 */
#define PKT_ALT_DECODE       0x00000800  /* this packet has been normalized by telnet
                                             (only set when we must look at an alernative buffer)
                                         */
#define PKT_STREAM_TWH       0x00001000
#define PKT_IGNORE_PORT      0x00002000  /* this packet should be ignored, based on port */
#define PKT_INLINE_DROP      0x20000000
#define PKT_OBFUSCATED       0x40000000  /* this packet has been obfuscated */
#define PKT_LOGGED           0x80000000  /* this packet has been logged */
/*  D A T A  S T R U C T U R E S  *********************************************/

/* 
 * Ethernet header
 */

typedef struct _EtherHdr
{
    u_int8_t ether_dst[6];
    u_int8_t ether_src[6];
    u_int16_t ether_type;

}         EtherHdr;

/* tcpdump shows us the way to cross platform compatibility */
#define IP_VER(iph)    (((iph)->ip_verhl & 0xf0) >> 4)
#define IP_HLEN(iph)   ((iph)->ip_verhl & 0x0f)

/* we need to change them as well as get them */
#define SET_IP_VER(iph, value)  ((iph)->ip_verhl = (((iph)->ip_verhl & 0x0f) | (value << 4)))
#define SET_IP_HLEN(iph, value)  ((iph)->ip_verhl = (((iph)->ip_verhl & 0xf0) | (value & 0x0f)))

typedef struct _IPHdr
{
    u_int8_t ip_verhl;      /* version & header length */
    u_int8_t ip_tos;        /* type of service */
    u_int16_t ip_len;       /* datagram length */
    u_int16_t ip_id;        /* identification  */
    u_int16_t ip_off;       /* fragment offset */
    u_int8_t ip_ttl;        /* time to live field */
    u_int8_t ip_proto;      /* datagram protocol */
    u_int16_t ip_csum;      /* checksum */
    u_int32_t ip_src;  /* source IP */
    u_int32_t ip_dst;  /* dest IP */
}      IPHdr;

/* more macros for TCP offset */
#define TCP_OFFSET(tcph)        (((tcph)->th_offx2 & 0xf0) >> 4)
#define TCP_X2(tcph)            ((tcph)->th_offx2 & 0x0f)

/* we need to change them as well as get them */
#define SET_TCP_OFFSET(tcph, value)  ((tcph)->th_offx2 = (((tcph)->th_offx2 & 0x0f) | (value << 4)))
#define SET_TCP_X2(tcph, value)  ((tcph)->th_offx2 = (((tcph)->th_offx2 & 0xf0) | (value & 0x0f)))

typedef struct _TCPHdr
{
    u_int16_t th_sport;     /* source port */
    u_int16_t th_dport;     /* destination port */
    u_int32_t th_seq;       /* sequence number */
    u_int32_t th_ack;       /* acknowledgement number */
    u_int8_t th_offx2;     /* offset and reserved */
    u_int8_t th_flags;
    u_int16_t th_win;       /* window */
    u_int16_t th_sum;       /* checksum */
    u_int16_t th_urp;       /* urgent pointer */

}       TCPHdr;

typedef struct _UDPHdr
{
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_chk;

}       UDPHdr;

typedef struct _ICMPHdr
{
    u_int8_t type;
    u_int8_t code;
    u_int16_t csum;
    union
    {
        u_int8_t pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            u_int16_t id;
            u_int16_t seq;
        } idseq;

        int sih_void;

        struct pmtu 
        {
            u_int16_t ipm_void;
            u_int16_t nextmtu;
        } pmtu;

        struct rtradv 
        {
            u_int8_t num_addrs;
            u_int8_t wpa;
            u_int16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union 
    {
        /* timestamp */
        struct ts 
        {
            u_int32_t otime;
            u_int32_t rtime;
            u_int32_t ttime;
        } ts;
        
        /* IP header for unreach */
        struct ih_ip  
        {
            IPHdr *ip;
            /* options and then 64 bits of data */
        } ip;
        
        struct ra_addr 
        {
            u_int32_t addr;
            u_int32_t preference;
        } radv;

        u_int32_t mask;

        char    data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data

}        ICMPHdr;


typedef struct _Options
{
    u_int8_t code;
    u_int8_t len; /* length of the data section */
    u_int8_t *data;
}        Options;

typedef struct _Packet
{
	struct sk_buff * skb;
	struct pintercept_pkthdr *pkth;   /* BPF data */
    u_int8_t *pkt;              /* base pointer to the raw packet data  yang 指向实际decode的数据*/

    EtherHdr *eh;               /* standard TCP/IP/Ethernet/ARP headers */
    
    IPHdr *iph, *orig_iph;   /* and orig. headers for ICMP_*_UNREACH family  指向实际数据的IP层  */
    u_int32_t ip_options_len;//IP头部中超过20字节的可选字段长度，例如IP头部总共30字节，则该字段为30-20
    u_int8_t *ip_options_data;//IP头部有可能有可选字段，正常情况IP头部为20字节，如果超过20字节，则ip_options_data指向新的超过20字节数据部分

    TCPHdr *tcph, *orig_tcph;//指向实际数据的TCP层
    u_int32_t tcp_options_len;
    u_int8_t *tcp_options_data;

    UDPHdr *udph, *orig_udph;//指向实际数据的UDP
	ICMPHdr *icmph, *orig_icmph;//指向实际数据的ICMP

    u_int8_t *data;         /* packet payload pointer 解除隧道后并去掉实际数据的IP层UDP层后的应用数据 */
    u_int16_t dsize;        /* packet payload size  解除隧道后并去掉实际数据的IP层UDP层后的应用数据长度 */
    u_int16_t alt_dsize;    /* the dsize of a packet before munging (used for log)*/

    u_int16_t actual_ip_len;/* for logging truncated packets (usually by a small snaplen)  IP头部长度 */

    u_int8_t frag_flag;     /* flag to indicate a fragmented packet   标示该包是否是分配包的一部分 */
/*
分片参考http://blog.csdn.net/zhaoneiep/article/details/5544595
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Identification     |R|DF|MF|   Fragment Offset   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|<-------------16-------------->|<--3-->|<---------13---------->| 
Identification：发送端发送的IP数据包标识字段都是一个唯一值，该值在分片时被复制到每个片中。 该值相同表面是同一个数据包
R：保留未用。
DF：Don't Fragment，“不分片”位，如果将这一比特置1 ，IP层将不对数据报进行分片。
MF：More Fragment，“更多的片”，除了最后一片外，其他每个组成数据报的片都要把该比特置1。
Fragment Offset：该片偏移原始数据包开始处的位置。偏移的字节数是该值乘以8。表示相对第一个包的位置，以便接收主机根据偏移量进行数据重组。
*/
    u_int16_t frag_offset;  /* fragment offset number YANG IP层的分片信息  最终存的是分片信息的后13位 如果为0表示这个包可能是第一个分片包，或者后面没有分片包  p->frag_offset &= 0x1FFF;  后13位相同则表明是同一个数据包 */

        //这三个表示分片的前三个位，参考分片相关知识  
    u_int8_t mf;            /* more fragments flag 为1表示该包后面还有有分片包，为0表示后面没有分片了， */
    u_int8_t df;            /* don't fragment flag */
    u_int8_t rf;                  /* IP reserved bit */

    u_int16_t sp;           /* source port (TCP/UDP) 解除隧道头部后的 值*/
    u_int16_t dp;           /* dest port (TCP/UDP) */
    u_int16_t orig_sp;      /* source port (TCP/UDP) of original datagram */
    u_int16_t orig_dp;      /* dest port (TCP/UDP) of original datagram */
    u_int32_t caplen;

    u_int8_t uri_count;     /* number of URIs in this packet */

    void *ssnptr;           /* for tcp session tracking info... */
    void *fragtracker;      /* for ip fragmentation tracking info... */
    void *flow;             /* for flow info */
    void *streamptr;        /* for tcp pkt dump */
    
    Options ip_options[IP_OPTMAX]; /* ip options decode structure */
    u_int32_t ip_option_count;  /* number of options in this packet */
    u_char ip_lastopt_bad;  /* flag to indicate that option decoding was
                               halted due to a bad option */
    Options tcp_options[TCP_OPTLENMAX];    /* tcp options decode struct */
    u_int32_t tcp_option_count;
    u_char tcp_lastopt_bad;  /* flag to indicate that option decoding was
                                halted due to a bad option */

    u_int8_t csum_flags;        /* checksum flags */
    u_int32_t packet_flags;     /* special flags for the packet */
    u_int32_t bytes_to_inspect; /* Number of bytes to check against rules */
//    int preprocessors;          /* flags for preprocessors to check */
} Packet;

typedef struct s_pseudoheader
{
    u_int32_t sip, dip; 
    u_int8_t  zero;     
    u_int8_t  protocol; 
    u_int16_t len; 

} PSEUDO_HDR;

/* Default classification for decoder alerts */
#define DECODE_CLASS 25 

typedef struct _DecoderFlags
{
    char decode_alerts;   /* if decode.c alerts are going to be enabled */
    char drop_alerts;     /* drop alerts from decoder */
    char tcpopt_experiment;  /* TcpOptions Decoder */
    char drop_tcpopt_experiment; /* Drop alerts from TcpOptions Decoder */
    char tcpopt_obsolete;    /* Alert on obsolete TCP options */
    char drop_tcpopt_obsolete; /* Drop on alerts from obsolete TCP options */
    char tcpopt_ttcp;        /* Alert on T/TCP options */
    char drop_tcpopt_ttcp;   /* Drop on alerts from T/TCP options */
    char tcpopt_decode;      /* alert on decoder inconsistencies */
    char drop_tcpopt_decode; /* Drop on alerts from decoder inconsistencies */
    char ipopt_decode;      /* alert on decoder inconsistencies */
    char drop_ipopt_decode; /* Drop on alerts from decoder inconsistencies */
} DecoderFlags;

#define        ALERTMSG_LENGTH 256

typedef unsigned int (*grinder_t)(Packet *, struct pintercept_pkthdr *, u_char *);  /* ptr to the packet processor */
extern grinder_t grinder;


/* dbg */
#define DEBUG_ALL             0xffffffff
#define DEBUG_INIT            0x00000001  /* 1 */
#define DEBUG_CONFIGRULES     0x00000002  /* 2 */
#define DEBUG_PLUGIN          0x00000004  /* 4 */
#define DEBUG_DATALINK        0x00000008  /* 8 */
#define DEBUG_IP              0x00000010  /* 16 */
#define DEBUG_TCPUDP          0x00000020  /* 32 */
#define DEBUG_DECODE          0x00000040  /* 64 */
#define DEBUG_LOG             0x00000080  /* 128 */
#define DEBUG_MSTRING         0x00000100  /* 256 */
#define DEBUG_PARSER          0x00000200  /* 512 */
#define DEBUG_PLUGBASE        0x00000400  /* 1024 */
#define DEBUG_RULES           0x00000800  /* 2048 */
#define DEBUG_FLOW            0x00001000  /* 4096 */
#define DEBUG_STREAM          0x00002000  /* 8192 */
#define DEBUG_PATTERN_MATCH   0x00004000  /* 16384 */
#define DEBUG_DETECT          0x00008000  /* 32768 */
#define DEBUG_CONVERSATION    0x00010000  /* 65536 */
#define DEBUG_FRAG            0x00020000  /* 131072 */
#define DEBUG_HTTP_DECODE     0x00040000  /* 262144 */
#define DEBUG_PORTSCAN2       0x00080000  /* 524288 / (+ conv2 ) 589824 */
#define DEBUG_RPC             0x00100000  /* 1048576 */
#define DEBUG_FLOWSYS         0x00200000  /* 2097152 */
#define DEBUG_HTTPINSPECT     0x00400000  /* 4194304 */
#define DEBUG_STREAM_STATE    0x00800000  /* 8388608 */
#define DEBUG_ASN1            0x01000000  /* 16777216 */

//#define LONG_PKT_ENABLE
//#define SHORT_PKT_ENABLE

//#define DEBUG
#define DBG_WARNING
#ifdef DEBUG
#define DEBUG_WRAP(x) x
#define SnortEventqAdd(x...)
#define DisableDetect(x)
#define ErrorMessage(x...)
#define LogMessage printk
#define FatalError  printk

#define STD_BUF 1024

void DebugMessageFunc(int level, char * file, int line, char *fmt, ...);
char *snort_strdup(char *str);

#define DebugMessage(a, b...) DebugMessageFunc(a, __FILE__, __LINE__, ## b)
#else
#define DEBUG_WRAP(x)
#define SnortEventqAdd(x...)
#define DisableDetect(x)
#define ErrorMessage(x...)
#define LogMessage(x...)
#define FatalError  printk

#define STD_BUF 1024
#endif


/*  P R O T O T Y P E S  ******************************************************/
unsigned int DecodeEthPkt(Packet *, struct pintercept_pkthdr *, u_int8_t *);
unsigned int DecodeIP(u_int8_t *, const u_int32_t, Packet *);
unsigned int DecodeTCP(u_int8_t *, const u_int32_t, Packet *);
unsigned int DecodeUDP(u_int8_t *, const u_int32_t, Packet *);
unsigned int DecodeICMP(u_int8_t * pkt, const u_int32_t len, Packet * p);
unsigned int DecodeIPOptions(u_int8_t *, u_int32_t, Packet *);
unsigned int DecodeTCPOptions(u_int8_t *, u_int32_t, Packet *);
unsigned int DecodeIPOptions(u_int8_t *, u_int32_t, Packet *);


extern int g_drop_pkt;
extern int g_skip_pkt;

#define MTP_AUTH_INFO_LEN 32//sizeof(m_d100_ah)总共32字节

#endif                /* __DECODE_H__ */

//2004.11.6
//xdang
//cs nudt, PRC


/* the libpintercept is provided by Dr.Zhang */

#ifndef PINTERCEPT_H
#define PINTERCEPT_H

#include <linux/time.h>

#define MAX_PACKET_LEN		1600
struct packet_attribute
{
	unsigned char *packet;
	int	snap_len;
	int	snap_sec;
	int	snap_usec;
};

/* xdang modified here 2004-11-6 */
/*** !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ***/
/* WATCH OUT: this is the same as the definition of struct pcap_pkthdr */
/* Just for compliance */ 
struct pintercept_pkthdr {
	struct timeval ts;	/* time stamp  yang 接收数据包的时间 */
	u_int32_t caplen;	/* actually captured packet length  去掉隧道头部后的报文长度 */
	u_int32_t len;	        /* packet length: same as caplen for yang 和caplen相同赋值 pkthdr->caplen = pkthdr->len;
				   the moment */
};
/* xdang */

typedef void (*pintercept_handler)(struct packet_attribute *pkt);

#endif


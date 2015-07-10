/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the RAW-IP module.
 *
 * Version:	@(#)raw.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _RAW_H
#define _RAW_H


#include <net/protocol.h>
#include <linux/icmp.h>

extern struct proto raw_prot;

void raw_icmp_error(struct sk_buff *, int, u32);
int raw_local_deliver(struct sk_buff *, int);

extern int 	raw_rcv(struct sock *, struct sk_buff *);

#define RAW_HTABLE_SIZE	MAX_INET_PROTOS

/*
tcp udp和raw的hash
union {
		struct inet_hashinfo	*hashinfo; //tcp_hashinfo
		struct udp_table	*udp_table; //udp_table
		struct raw_hashinfo	*raw_hash; //raw_v4_hashinfo
	} h;
*/ //raw套接字的struct sock加入到这里面
struct raw_hashinfo {
	rwlock_t lock;
	struct hlist_head ht[RAW_HTABLE_SIZE];
};

#ifdef CONFIG_PROC_FS
extern int  raw_proc_init(void);
extern void raw_proc_exit(void);

struct raw_iter_state {
	struct seq_net_private p;
	int bucket;
	struct raw_hashinfo *h;
};

#define raw_seq_private(seq) ((struct raw_iter_state *)(seq)->private)
void *raw_seq_start(struct seq_file *seq, loff_t *pos);
void *raw_seq_next(struct seq_file *seq, void *v, loff_t *pos);
void raw_seq_stop(struct seq_file *seq, void *v);
int raw_seq_open(struct inode *ino, struct file *file,
		 struct raw_hashinfo *h, const struct seq_operations *ops);

#endif

void raw_hash_sk(struct sock *sk);
void raw_unhash_sk(struct sock *sk);
/*套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)
*/
struct raw_sock {
	/* inet_sock has to be the first member */
	struct inet_sock   inet;
	struct icmp_filter filter;
	u32		   ipmr_table;
};

static inline struct raw_sock *raw_sk(const struct sock *sk)
{
	return (struct raw_sock *)sk;
}

#endif	/* _RAW_H */

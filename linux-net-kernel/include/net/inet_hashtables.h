/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 * Authors:	Lotsa people, from code originally in tcp
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _INET_HASHTABLES_H
#define _INET_HASHTABLES_H


#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>

#include <net/inet_connection_sock.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/tcp_states.h>
#include <net/netns/hash.h>

#include <asm/atomic.h>
#include <asm/byteorder.h>

/* This is for all connections with a full identity, no wildcards.
 * One chain is dedicated to TIME_WAIT sockets.
 * I'll experiment with dynamic table growth later.
 */
 /*
 * 用来管理TCP状态除LISTEN之外的传输控制块的散列表
 */ //inet_ehash_bucket的图像化理解可以参考，樊东东，下册P735
 //hash表头为inet_hashinfo的ehash
struct inet_ehash_bucket {
	/*
	 * 用于链接传输控制块
//服务器端三次握手成功后对应的struct tcp_sock添加到这个hash表头中，客户端在发送syn之前如果检查端口等可用，
则在__inet_check_established中的__sk_nulls_add_node_rcu把sk添加到ehash中

	 */
	struct hlist_nulls_head chain;
	/*
	 * 用于链接TIME_WAIT状态的传输控制块
	 */
	struct hlist_nulls_head twchain;//链表中连接的是inet_timewait_sock结构，见__inet_twsk_hashdance
};

/* There are a few simple rules, which allow for local port reuse by
 * an application.  In essence:
 *
 *	1) Sockets bound to different interfaces may share a local port.
 *	   Failing that, goto test 2.
 *	2) If all sockets have sk->sk_reuse set, and none of them are in
 *	   TCP_LISTEN state, the port may be shared.
 *	   Failing that, goto test 3.
 *	3) If all sockets are bound to a specific inet_sk(sk)->rcv_saddr local
 *	   address, and none of them are the same, the port may be
 *	   shared.
 *	   Failing this, the port cannot be shared.
 *
 * The interesting point, is test #2.  This is what an FTP server does
 * all day.  To optimize this case we use a specific flag bit defined
 * below.  As we add sockets to a bind bucket list, we perform a
 * check of: (newsk->sk_reuse && (newsk->sk_state != TCP_LISTEN))
 * As long as all sockets added to a bind bucket pass this test,
 * the flag bit will be set.
 * The resulting situation is that tcp_v[46]_verify_bind() can just check
 * for this flag bit, if it is set and the socket trying to bind has
 * sk->sk_reuse set, we don't even have to walk the owners list at all,
 * we return that it is ok to bind this socket to the requested local port.
 *
 * Sounds like a lot of work, but it is worth it.  In a more naive
 * implementation (ie. current FreeBSD etc.) the entire list of ports
 * must be walked for each data port opened by an ftp server.  Needless
 * to say, this does not scale at all.  With a couple thousand FTP
 * users logged onto your box, isn't it nice to know that new data
 * ports are created in O(1) time?  I thought so. ;-)	-DaveM
 */
struct inet_bind_bucket1 {
#ifdef CONFIG_NET_NS
	struct net		*ib_net;
#endif
	unsigned short		port;
	signed short		fastreuse;
	int			num_owners;
	struct hlist_node	node;
	struct hlist_head	owners;
};
//赋值在这个函数中inet_bind_hash ，
//存放的是端口绑定信息， inet_bind_bucket_create创建   __inet_put_port释放
//该结构最终添加到inet_bind_hashbucket结构的chain中
//该结构是在客户端connect分配客户端端口的时候有用到，在做客户端connect的时候创建inet_bind_bucket空间
//该结构体最终的结果是，struct sock被添加到inet_bind_bucket结构的owners链表中(inet_bind_hash)，然后该inet_bind_bucket通过node节点加入到tcp_hashinfo的chain中，inet_bind_hashbucket中的(inet_bind_bucket_create)
/*该结构在三次握手成功的时候首先通过owners连接到inet_connection_sock中的icsk_bind_hash，当在端口连接过程中进入timewait的过程中该inet_bind_bucket会从新连接到
tw->tw_bind_node,见inet_timewait_sock中，所以三次握手端口的timewait 释放sk的时候，并没有释放掉该bind桶，见__inet_twsk_hashdance*/
//图形化结构理解参考樊东东下P775            释放的地方在__inet_put_port
struct inet_bind_bucket { //存储在inet_hashinfo中的bhash表中，对应的hashbucket为inet_bind_hashbucket        
//所有的inet_bind_bucket实例通过它里面的node成员连接在一起，然后添加到inet_bind_hashbucket的chain中，最后在把chain连接到inet_hashinfo中的bhash中
//同时在应用程序客户端connect或者服务器端bind的时候，通过owners把该inet_bind_bucket添加到struct sock中的sk_bind_node中,同时inet_csk(sk)->icsk_bind_hash指向这个inet_bind_bucket，
//这样inet_bind_bucket就可以和struct sock关联起来。见inet_bind_hash
#ifdef CONFIG_NET_NS
	struct net		*ib_net;
#endif
	/*
	 * 已绑定的端口号
	 */
	unsigned short		port;
	/*
	 * 标识端口是否能重用
	 * 0: 此端口已通过bind系统调用绑定，但不能重用
	 * 1: 此端口已经通过bind系统调用绑定，且能重用  sk->sk_reuse可以重用的话，这个值就可以重用
	 * -1: 此端口被客户端动态绑定(由inet_hash_connection()进行绑定)
	 */
	signed short		fastreuse;//__inet_hash_connect客户端连接在检查fastreuse是否可复用时，还得继续检查__inet_check_established，inet_csk_get_port
	int			num_owners;//被sk引用次数，inet_bind_hash
	/*
	 * 用来存储bhash散列表的节点， 该inet_bind_bucket通过该node添加到inet_bind_hashbucket的chain中   inet_bind_hash  inet_bind_bucket_create
	 */
	struct hlist_node	node;
	/*
	 * 为绑定该端口上的传输控制块链表 
	 *///通过owners把该inet_bind_bucket添加到struct sock中的sk_bind_node中，这样inet_bind_bucket就可以和struct sock关联起来。
	 //这个最开始指向的是sk->sk_bind_node，当进入timewait的时候指向tw->tw_bind_node，所以bind桶在wait1状态切换到timewait状态的时候，在释放sk时，不会释放掉bind信息。见tcp_time_wait
	struct hlist_head	owners; //对应的struct sock通过sk_bind_node成员添加到该owners中  见inet_bind_hash
	//该结构通过owners加入到struct sock里面的sk_bind_node中
	/*在time_wait过程中，该inet_hash_bucket会通过owners指向sk,变为指向tw->tw_bind_node,见inet_timewait_sock。所以在进入time_wait状态，
	在tcp_time_wait中释放了sk,但其之前bind相关的inet_bind_bucket桶并没有释放，是在最好close状态的时候才释放，见__inet_twsk_hashdance*/
};

static inline struct net *ib_net(struct inet_bind_bucket *ib)
{
	return read_pnet(&ib->ib_net);
}

#define inet_bind_bucket_for_each(tb, pos, head) \
	hlist_for_each_entry(tb, pos, head, node)

struct inet_bind_hashbucket1 {
	spinlock_t		lock;
	struct hlist_head	chain;
};
//该结构由inet_hashinfo中的bhash指向  该结构是在客户端connect分配客户端端口的时候有用到
//TCP中使用inet_bind_hashbucket散列表来管理已绑定端口。inet_bind_bucket实例通过它里面的node成员连接到inet_hashinfo中的bhash中
//图形化理解可以参考樊东东下 P775，hash桶的头指针为这个，其中的inet_bind_bucket通过node全部添加到chain链表中
struct inet_bind_hashbucket {//所有的inet_bind_bucket实例通过它里面的node成员连接在一起，然后添加到inet_bind_hashbucket的chain中，最后在把chain连接到inet_hashinfo中的bhash中
	/*
	 * 控制该链表的读写锁
	 */
	spinlock_t		lock;
	/*
	 * 用于建立端口绑定信息块，结构体为inet_bind_bucket， 即inet_bind_bucket结构链表 inet_bind_bucket_create
	 */
	struct hlist_head	chain;
};

/*
 * Sockets can be hashed in established or listening table
 * We must use different 'nulls' end-of-chain value for listening
 * hash table, or we might find a socket that was closed and
 * reallocated/inserted into established hash table
 */
#define LISTENING_NULLS_BASE (1U << 29)
struct inet_listen_hashbucket {
	spinlock_t		lock;
	struct hlist_nulls_head	head;
};

/* This is for listening sockets, thus all sockets which possess wildcards. */
#define INET_LHTABLE_SIZE	32	/* Yes, really, this is all you need. */

struct inet_hashinfo1 {
	/* This is for sockets with full identity only.  Sockets here will
	 * always be without wildcards and will have the following invariant:
	 *
	 *          TCP_ESTABLISHED <= sk->sk_state < TCP_CLOSE
	 *
	 * TIME_WAIT sockets use a separate chain (twchain).
	 */
	struct inet_ehash_bucket	*ehash;
	spinlock_t			*ehash_locks;
	unsigned int			ehash_mask;
	unsigned int			ehash_locks_mask;

	/* Ok, let's try this, I give up, we do need a local binding
	 * TCP hash as well as the others for fast bind/connect.
	 */
	struct inet_bind_hashbucket	*bhash;

	unsigned int			bhash_size;
	/* 4 bytes hole on 64 bit */

	struct kmem_cache		*bind_bucket_cachep;

	/* All the above members are written once at bootup and
	 * never written again _or_ are predominantly read-access.
	 *
	 * Now align to a new cache line as all the following members
	 * might be often dirty.
	 */
	/* All sockets in TCP_LISTEN state will be in here.  This is the only
	 * table where wildcard'd TCP sockets can exist.  Hash function here
	 * is just local port number.
	 */
	struct inet_listen_hashbucket	listening_hash[INET_LHTABLE_SIZE]
					____cacheline_aligned_in_smp;

	atomic_t			bsockets;
};
/*
 * TCP传输层中用一个inet_hashinfo结构类型的全局变量
 * tcp_hashinfo对所有的散列表进行集中管理。
  //tcp_death_row里面的hashinfo指向变量tcp_hashinfo，也就是所有的inethash_info的头在这里
 */
/*
tcp udp和raw的hash
union {
		struct inet_hashinfo	*hashinfo; //tcp_hashinfo
		struct udp_table	*udp_table; //udp_table
		struct raw_hashinfo	*raw_hash; //raw_v4_hashinfo
	} h;
*/

//tcp_hashinfo的图像化理解可以参考，樊东东，下册P734
struct inet_hashinfo {
	/* This is for sockets with full identity only.  Sockets here will
	 * always be without wildcards and will have the following invariant:
	 *
	 *          TCP_ESTABLISHED <= sk->sk_state < TCP_CLOSE
	 *
	 * TIME_WAIT sockets use a separate chain (twchain).
	 */
	/*
	 * ehash指向一个大小为ehash_size的inet_ehash_bucket结构类型的散列
	 * 表，用来管理TCP状态除LISTEN之外的传输控制块的散列表

	 tcp表又分成了三张表ehash, bhash, listening_hash，其中ehash, listening_hash对应于socket处在TCP的ESTABLISHED, LISTEN状态，bhash对应于socket
	 已绑定了本地地址。三者间并不互斥，如一个socket可同时在bhash和ehash中，由于TIME_WAIT是一个比较特殊的状态，所以ehash又分成了chain和twchain，
	 为TIME_WAIT的socket单独形成一张表。
	 */
	 //inet_timewait_sock通过__inet_twsk_hashdance加入到该ehash中的twrefcnt += hash(sk, tw);。服务器端accept的时候，是在建立连接成功的时候才放到该ehash中的。
	 //客户端connect的时候，立马加入到该hash中，见__inet_hash_connect
	struct inet_ehash_bucket	*ehash;//见inet_ehash_bucket函数  这个hash桶里面的是多个连接成功的sock,timewait的sock也在这里面
	spinlock_t			*ehash_locks;
	unsigned int			ehash_size;
	unsigned int			ehash_locks_mask;

	/* Ok, let's try this, I give up, we do need a local binding
	 * TCP hash as well as the others for fast bind/connect.
	 */
	/*
	 * 主要用来存储已绑定端口的信息  inet_bind_bucket  该结构是在客户端connect分配客户端端口的时候有用到,在连接建立过程中只用ehash和listening_hash
	 */////所有的inet_bind_bucket实例通过它里面的node成员连接在一起，然后添加到inet_bind_hashbucket的chain中，最后在把chain连接到inet_hashinfo中的bhash中
    //如果是客户端连接，则在connect的时候调用inet_bind_hash，然后添加到该hash桶中，见__inet_hash_connect
    //在连接端口，进入timewait状态的时候，inet_timewait_sock也会添加到该bhash中，见__inet_twsk_hashdance
    //释放函数在inet_bind_bucket
	struct inet_bind_hashbucket	*bhash;//被绑定的端口信息会一直在该。下次绑定其他端口或者分配端口的时候需要用这个遍历检查。图形化结构理解参考樊东东下P775
	unsigned int			bhash_size;
	/* 4 bytes hole on 64 bit */
	/*
	 * 用来分配inet_bind_hashbucket结构的后备高速缓存
	 */
	struct kmem_cache		*bind_bucket_cachep;

	/* All the above members are written once at bootup and
	 * never written again _or_ are predominantly read-access.
	 *
	 * Now align to a new cache line as all the following members
	 * might be often dirty.
	 */
	/* All sockets in TCP_LISTEN state will be in here.  This is the only
	 * table where wildcard'd TCP sockets can exist.  Hash function here
	 * is just local port number.
	 */
	/*
	 * 用来存储管理LISTEN状态的传输控制块的散列表。在listen状态的时候进入，见inet_csk_listen_start
	 */
	struct inet_listen_hashbucket	listening_hash[INET_LHTABLE_SIZE];// ____cacheline_aligned_in_smp;
	/*
	 * 应该是已绑定的套接字的数量 inet_bind_hash
	 */
	atomic_t			bsockets;
};

static inline struct inet_ehash_bucket *inet_ehash_bucket(
	struct inet_hashinfo *hashinfo,
	unsigned int hash)
{
	return &hashinfo->ehash[hash & hashinfo->ehash_mask];
}

static inline spinlock_t *inet_ehash_lockp(
	struct inet_hashinfo *hashinfo,
	unsigned int hash)
{
	return &hashinfo->ehash_locks[hash & hashinfo->ehash_locks_mask];
}

static inline int inet_ehash_locks_alloc(struct inet_hashinfo *hashinfo)
{
	unsigned int i, size = 256;
#if defined(CONFIG_PROVE_LOCKING)
	unsigned int nr_pcpus = 2;
#else
	unsigned int nr_pcpus = num_possible_cpus();
#endif
	if (nr_pcpus >= 4)
		size = 512;
	if (nr_pcpus >= 8)
		size = 1024;
	if (nr_pcpus >= 16)
		size = 2048;
	if (nr_pcpus >= 32)
		size = 4096;
	if (sizeof(spinlock_t) != 0) {
#ifdef CONFIG_NUMA
		if (size * sizeof(spinlock_t) > PAGE_SIZE)
			hashinfo->ehash_locks = vmalloc(size * sizeof(spinlock_t));
		else
#endif
		hashinfo->ehash_locks =	kmalloc(size * sizeof(spinlock_t),
						GFP_KERNEL);
		if (!hashinfo->ehash_locks)
			return ENOMEM;
		for (i = 0; i < size; i++)
			spin_lock_init(&hashinfo->ehash_locks[i]);
	}
	hashinfo->ehash_locks_mask = size - 1;
	return 0;
}

static inline void inet_ehash_locks_free(struct inet_hashinfo *hashinfo)
{
	if (hashinfo->ehash_locks) {
#ifdef CONFIG_NUMA
		unsigned int size = (hashinfo->ehash_locks_mask + 1) *
							sizeof(spinlock_t);
		if (size > PAGE_SIZE)
			vfree(hashinfo->ehash_locks);
		else
#endif
		kfree(hashinfo->ehash_locks);
		hashinfo->ehash_locks = NULL;
	}
}

extern struct inet_bind_bucket *
		    inet_bind_bucket_create(struct kmem_cache *cachep,
					    struct net *net,
					    struct inet_bind_hashbucket *head,
					    const unsigned short snum);
extern void inet_bind_bucket_destroy(struct kmem_cache *cachep,
				     struct inet_bind_bucket *tb);

static inline int inet_bhashfn(struct net *net,
		const __u16 lport, const int bhash_size)
{
	return (lport + net_hash_mix(net)) & (bhash_size - 1);
}

extern void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
			   const unsigned short snum);

/* These can have wildcards, don't try too hard. */
static inline int inet_lhashfn(struct net *net, const unsigned short num)
{
	return (num + net_hash_mix(net)) & (INET_LHTABLE_SIZE - 1);
}

//通过sk来接收一个hash 键值
static inline int inet_sk_listen_hashfn(const struct sock *sk)
{
	return inet_lhashfn(sock_net(sk), inet_sk(sk)->inet_num);
}

/* Caller must disable local BH processing. */
extern void __inet_inherit_port(struct sock *sk, struct sock *child);

extern void inet_put_port(struct sock *sk);

void inet_hashinfo_init(struct inet_hashinfo *h);

extern int __inet_hash_nolisten(struct sock *sk, struct inet_timewait_sock *tw);
extern void inet_hash(struct sock *sk);
extern void inet_unhash(struct sock *sk);

extern struct sock *__inet_lookup_listener(struct net *net,
					   struct inet_hashinfo *hashinfo,
					   const __be32 daddr,
					   const unsigned short hnum,
					   const int dif);

static inline struct sock *inet_lookup_listener(struct net *net,
		struct inet_hashinfo *hashinfo,
		__be32 daddr, __be16 dport, int dif)
{
	return __inet_lookup_listener(net, hashinfo, daddr, ntohs(dport), dif);
}

/* Socket demux engine toys. */
/* What happens here is ugly; there's a pair of adjacent fields in
   struct inet_sock; __be16 dport followed by __u16 num.  We want to
   search by pair, so we combine the keys into a single 32bit value
   and compare with 32bit value read from &...->dport.  Let's at least
   make sure that it's not mixed with anything else...
   On 64bit targets we combine comparisons with pair of adjacent __be32
   fields in the same way.
*/
typedef __u32 __bitwise __portpair;
#ifdef __BIG_ENDIAN
#define INET_COMBINED_PORTS(__sport, __dport) \
	((__force __portpair)(((__force __u32)(__be16)(__sport) << 16) | (__u32)(__dport)))
#else /* __LITTLE_ENDIAN */
#define INET_COMBINED_PORTS(__sport, __dport) \
	((__force __portpair)(((__u32)(__dport) << 16) | (__force __u32)(__be16)(__sport)))
#endif

#if (BITS_PER_LONG == 64)
typedef __u64 __bitwise __addrpair;
#ifdef __BIG_ENDIAN
#define INET_ADDR_COOKIE(__name, __saddr, __daddr) \
	const __addrpair __name = (__force __addrpair) ( \
				   (((__force __u64)(__be32)(__saddr)) << 32) | \
				   ((__force __u64)(__be32)(__daddr)));
#else /* __LITTLE_ENDIAN */
#define INET_ADDR_COOKIE(__name, __saddr, __daddr) \
	const __addrpair __name = (__force __addrpair) ( \
				   (((__force __u64)(__be32)(__daddr)) << 32) | \
				   ((__force __u64)(__be32)(__saddr)));
#endif /* __BIG_ENDIAN */
#define INET_MATCH(__sk, __net, __hash, __cookie, __saddr, __daddr, __ports, __dif)\
	(((__sk)->sk_hash == (__hash)) && net_eq(sock_net(__sk), (__net)) &&	\
	 ((*((__addrpair *)&(inet_sk(__sk)->inet_daddr))) == (__cookie))  &&	\
	 ((*((__portpair *)&(inet_sk(__sk)->inet_dport))) == (__ports))   &&	\
	 (!((__sk)->sk_bound_dev_if) || ((__sk)->sk_bound_dev_if == (__dif))))
#define INET_TW_MATCH(__sk, __net, __hash, __cookie, __saddr, __daddr, __ports, __dif)\
	(((__sk)->sk_hash == (__hash)) && net_eq(sock_net(__sk), (__net)) &&	\
	 ((*((__addrpair *)&(inet_twsk(__sk)->tw_daddr))) == (__cookie)) &&	\
	 ((*((__portpair *)&(inet_twsk(__sk)->tw_dport))) == (__ports)) &&	\
	 (!((__sk)->sk_bound_dev_if) || ((__sk)->sk_bound_dev_if == (__dif))))
#else /* 32-bit arch */
#define INET_ADDR_COOKIE(__name, __saddr, __daddr)
#define INET_MATCH(__sk, __net, __hash, __cookie, __saddr, __daddr, __ports, __dif)	\
	(((__sk)->sk_hash == (__hash)) && net_eq(sock_net(__sk), (__net))	&&	\
	 (inet_sk(__sk)->inet_daddr	== (__saddr))		&&	\
	 (inet_sk(__sk)->inet_rcv_saddr	== (__daddr))		&&	\
	 ((*((__portpair *)&(inet_sk(__sk)->inet_dport))) == (__ports))	&&	\
	 (!((__sk)->sk_bound_dev_if) || ((__sk)->sk_bound_dev_if == (__dif))))
#define INET_TW_MATCH(__sk, __net, __hash,__cookie, __saddr, __daddr, __ports, __dif)	\
	(((__sk)->sk_hash == (__hash)) && net_eq(sock_net(__sk), (__net))	&&	\
	 (inet_twsk(__sk)->tw_daddr	== (__saddr))		&&	\
	 (inet_twsk(__sk)->tw_rcv_saddr	== (__daddr))		&&	\
	 ((*((__portpair *)&(inet_twsk(__sk)->tw_dport))) == (__ports)) &&	\
	 (!((__sk)->sk_bound_dev_if) || ((__sk)->sk_bound_dev_if == (__dif))))
#endif /* 64-bit arch */

/*
 * Sockets in TCP_CLOSE state are _always_ taken out of the hash, so we need
 * not check it for lookups anymore, thanks Alexey. -DaveM
 *
 * Local BH must be disabled here.
 */
extern struct sock * __inet_lookup_established(struct net *net,
		struct inet_hashinfo *hashinfo,
		const __be32 saddr, const __be16 sport,
		const __be32 daddr, const u16 hnum, const int dif);

static inline struct sock *
	inet_lookup_established(struct net *net, struct inet_hashinfo *hashinfo,
				const __be32 saddr, const __be16 sport,
				const __be32 daddr, const __be16 dport,
				const int dif)
{
	return __inet_lookup_established(net, hashinfo, saddr, sport, daddr,
					 ntohs(dport), dif);
}

static inline struct sock *__inet_lookup(struct net *net,
					 struct inet_hashinfo *hashinfo,
					 const __be32 saddr, const __be16 sport,
					 const __be32 daddr, const __be16 dport,
					 const int dif)
{
	u16 hnum = ntohs(dport);
	struct sock *sk = __inet_lookup_established(net, hashinfo,
				saddr, sport, daddr, hnum, dif);

	return sk ? : __inet_lookup_listener(net, hashinfo, daddr, hnum, dif);
}

static inline struct sock *inet_lookup(struct net *net,
				       struct inet_hashinfo *hashinfo,
				       const __be32 saddr, const __be16 sport,
				       const __be32 daddr, const __be16 dport,
				       const int dif)
{
	struct sock *sk;

	local_bh_disable();
	sk = __inet_lookup(net, hashinfo, saddr, sport, daddr, dport, dif);
	local_bh_enable();

	return sk;
}

static inline struct sock *__inet_lookup_skb(struct inet_hashinfo *hashinfo,
					     struct sk_buff *skb,
					     const __be16 sport,
					     const __be16 dport)
{
	struct sock *sk;
	const struct iphdr *iph = ip_hdr(skb);

	if (unlikely(sk = skb_steal_sock(skb)))
		return sk;
	else
		return __inet_lookup(dev_net(skb_dst(skb)->dev), hashinfo,
				     iph->saddr, sport,
				     iph->daddr, dport, inet_iif(skb));
}

extern int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk,
		u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		int (*hash)(struct sock *sk, struct inet_timewait_sock *twp));

extern int inet_hash_connect(struct inet_timewait_death_row *death_row,
			     struct sock *sk);
#endif /* _INET_HASHTABLES_H */

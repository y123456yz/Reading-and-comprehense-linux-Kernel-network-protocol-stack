/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

/* empty to "strongly type" an otherwise void parameter.
 */
struct request_values {
};

/*
 * 处理连接请求的函数指针表，其中包括用于发送SYN+ACK段、
 * ACK段、RST段的函数。TCP中，指向的实例为tcp_request_sock_ops。 timewait为tcp_timewait_sock_ops
 */
struct request_sock_ops {
	/*
	 * 所属协议族
	 */
	int		family;
	/*
	 * obj_size是tcp_request_sock结构长度，用于创建分配
	 * 连接请求块的高速缓存slab，该缓存在注册传输层协议
	 * 时创建，参见proto_register()。
	 */
	int		obj_size;
	struct kmem_cache	*slab;
	char		*slab_name;
	/*
	 * 发送SYN+ACK段的函数指针，TCP中为tcp_v4_send_synack()
	 */
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req);
	/*
	 * 发送ACK段的函数指针，TCP中为tcp_v4_reqsk_send_ack()
	 */
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);
	/*
	 * 发送RST段的函数指针，TCP中为tcp_v4_send_reset()
	 */
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	/*
	 * 析构函数，在释放连接请求块时被调用，用来清理释放资源。TCP中
	 * 为tcp_v4_reqsk_destructor()。
	 */
	void		(*destructor)(struct request_sock *req);
};

struct request_sock_ops1 {
	int		family;
	int		obj_size;
	struct kmem_cache	*slab;
	char		*slab_name;
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req,
				       struct request_values *rvp);
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb);
	void		(*destructor)(struct request_sock *req);
	void		(*syn_ack_timeout)(struct sock *sk,
					   struct request_sock *req);
};

/* struct request_sock - mini sock to represent a connection request
 */   
 //tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
 /*
 * 主要描述对对端的MSS、本端的接收窗口大小以及控制连接操作的信息，比如
 * 超时时间等
  tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
 */  //request_sock_queue中的listen_sock里面的hash表syn_table中存储的这个结构
 struct request_sock {
	/*
	 * 用来将request_sock结构实例链接成链表
	 */
	struct request_sock		*dl_next; /* Must be first member! */
	/*
	 * 客户端连接请求段中通告的MSS。如果无通告，则为初始值，
	 * 即RFC中建议的536
	 */
	u16				mss;
	/*
	 * 发送SYN+ACK段的次数，在达到系统设定的上限时，取消连接操作
	 */
	u8				retrans;
	u8				cookie_ts; /* syncookie: encode tcpopts in timestamp */
	/* The following two fields can be easily recomputed I think -AK */
	/*
	 * 标识本端的最大通告窗口，在生成SYN+ACK段时计算该值
	 */
	u32				window_clamp; /* window clamp at creation time */
	/*
	 * 标识在连接建立时本端接收窗口大小，初始化为0，在生成
	 * SYN+ACK段时计算该值。
	 */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	/*
	 * 下一个将要发送的ACK中的时间戳值。当一个包含最后发送ACK确认序号的
	 * 段到达时，该段中的时间戳被保存在ts_recent中
	 */
	u32				ts_recent;
	/*
	 * 服务端接收到连接请求，并发送SYN+ACK段作为应答后，等待
	 * 客户端确认的超时时间。一旦超时，会重新发送SYN+ACK段，
	 * 直到连接建立或重发次数达到上限
	 */
	unsigned long			expires;
	/*
	 * 处理连接请求的函数指针表，TCP中指向
	 * tcp_request_sock_ops
	 */
	const struct request_sock_ops	*rsk_ops;
	/*
	 * 指向对应状态的传输控制块。在连接建立之前无效，三次握手后会
	 * 创建对应的传输控制块，而此时连接请求块也完成了历史使命，
	 * 调用accept()将该连接请求块取走并释放(释放的是request_sock实例，
	 * 不是sock实例)
	 */
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};
struct request_sock1 {
	struct request_sock		*dl_next; /* Must be first member! */
	u16				mss;
	u8				retrans;
	u8				cookie_ts; /* syncookie: encode tcpopts in timestamp */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
	u32				ts_recent;
	unsigned long			expires;
	const struct request_sock_ops	*rsk_ops;
	struct sock			*sk;
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
/*
 * listen_sock结构用来存储连接请求块(连接尚未建立)，该结构
 * 的实例在listen系统调用之后才会被创建      request_sock_queue的listen_opt指向这里
 */ //见樊东东，P748 的图形化理解
 //连接建立定时器、保活定时器和FIN_WAIT_2定时器用的是同一个定时器，保活定时器tcp_keepalive_timer
 //服务器端应用程序listen的时候，来自客户端的半连接都会存储在这个结构中的
 //该结构在reqsk_alloc开辟空间，该结构式存的是半连接数。增加内核TCP SYN并发支持可以参考:http://blog.chinaunix.net/uid-20662820-id-3776090.html
struct listen_sock {   //服务器端发送的syn+ack的重传在inet_csk_reqsk_queue_prune中实现。该结构添加到sk在inet_csk_reqsk_queue_hash_add中。半连接超时或者关闭套接字，删除在inet_csk_reqsk_queue_removed
    /*
     * 实际分配用来保存SYN请求连接的request_sock结构数组的长度，这个值
     * 其值为nr_table_entries以2为底的对数，也就是下面的syn_table[]数组大小
     */
    u8          max_qlen_log;
    /* 3 bytes hole, try to use */
    /*
     * 当前连接请求块数目   半连接请求数目，
     */
    int         qlen;
    /*
     * 当前未重传过SYN+ACK段的请求块数目。如果每次建立连接都很顺利，
     * 三次握手的段没有重传，则qlen_young和qlen是一致的，有SYN+ACK段
     * 重传时会递减
     */
    int         qlen_young;
    /*
     * 用来记录连接建立定时器处理函数下次被激活时需处理的连接请求块
     * 散列表入口。在本次处理结束时将当前的入口保存到该字段中，在
     * 下次处理时就从该入口开始处理
     */
    int         clock_hand;
    /*
     * 用来计算SYN请求块散列表键值的随机数，该值在
     * reqsk_queue_alloc()中随机生成
     */
    u32         hash_rnd; //在搜索查询syn_talbe hash表的时候，需要用到该值
    /*
     * 实际分配用来保存SYN请求连接的request_sock结构数组的长度。见max_qlen_log，也就是下面的syn_table[]数组大小
     */ //这个值和struct sock中的sk_max_ack_backlog相同
    u32         nr_table_entries;//在函数reqsk_queue_alloc中赋值,最大的半连接数个数。增加内核TCP SYN并发支持可以参考:http://blog.chinaunix.net/uid-20662820-id-3776090.html
    /*
     * 调用listen时不仅使TCP进入LISTEN状态，同时还为SYN_RECV状态的
     * 请求连接控制块分配空间，其中syn_table散列表大小由listen系统
     * 调用的参数backlog控制
     */ //图形化理解参考樊东东P769
    //空间开辟在reqsk_queue_alloc中，表头是request_sock结构，里面的节点是tcp_request_sock结构，
    //这里面是nr_table_entries个指向struct request_sock的指针，也就是指针头个数和最大半连接数nr_table_entries是相同的
    struct request_sock *syn_table[0];//通过clock_hand指向对应的syn_table[clock_hand]散列表中，其实就是个hash表。
    //这个链表里面存储的是request_sock结构,也就是客户端SYN过来的时候创建。 这里面存的是TCP半连接请求块。收到SYN请求tcp_v4_conn_request的时候开辟空间，添加到hash表中。但三次握手成功第第三步后，会从这个hash中取出来放入到request_sock_queue里面的已连接请求链表中
    //连接请求块tcp_request_sock节点的添加在inet_csk_reqsk_queue_hash_add  查找在inet_csk_search_req，处理在inet_csk_reqsk_queue_prune
};


/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
/*
 * 在TCP传输控制块中有一个用于存放连接请求块(处于SYN_RECV状态以及
 * 已连接但未被accept的传输控制块)的容器
 */ ////见樊东东，P748 的图形化理解
 //该结构在inet_connection_sock中的icsk_accept_queue
struct request_sock_queue {
    /*
     * rskq_accept_head和rskq_accept_tail表示的链表保存的是
     * 已完成连接建立过程的连接请求块  服务器端accept的时候，struct sock是从这个队列上面取出来的
     */ //已经建立连接的连接的节点添加到这里，这些链表的节点信息结构体是tcp_request_sock。当应用程序调用accept函数后，会从这里面取走这个tcp_request_sock
    struct request_sock *rskq_accept_head;// //当应用程序accept的时候，会调用reqsk_queue_get_child取走这个新创建的sock，同时就需要把这个取出的tcp_request_sock释放掉
    struct request_sock *rskq_accept_tail;
    /*
     * 访问listen_opt以及listen_sock结构成员的同步控制读写锁
     */
    rwlock_t        syn_wait_lock;
    /*
     * 保存相关套接字TCP层的选项TCP_DEFER_ACCEPT的值，参见
     * TCP_DEFER_ACCEPT
     * 保存的是启用TCP_DEFER_ACCEPT时允许重传SYN+ACK段的次数。
     * 注意:如果启用了TCP_DEFER_ACCEPT选项，将使用rskq_defer_accept
     * 作为允许重传的最大次数，不再是sysctl_tcp_synack_retries，
     * 参见inet_csk_reqsk_queue_prune()。
     */
    u8          rskq_defer_accept;
    /* 3 bytes hole, try to pack */
    /*
     * 该实例在监听时建立，所以在应用程序未listen的时候是没有该结构存储的，也就是没有用来存储半连接请求的hash空间
     */
    struct listen_sock  *listen_opt; //还未完成连接的sock应该都在这里的syn_table hash表中，已经建立连接的request_sock会从这里面取出放入到放在前面的rskq_accept_head
};


extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	WARN_ON(req == NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

/*
 * 从已连接队列上取走第一个连接请求块，然后由该连接请求块获得已创建的子
 * 传输控制块，接着释放已完成建立连接的连接请求块，同时更新父传输控制块
 * 上已建立连接的数目，最后返回子传输控制块
 *///该函数在inet_csk_accept中调用。
 //服务器端三次握手成功后创建子sk的函数为tcp_v4_syn_recv_sock
static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue);

	//这两个关联的地方在reqsk_queue_add
	struct sock *child = req->sk;//当三次握手完成后，服务器端重新创建一个sock,见tcp_v4_syn_recv_sock里面的tcp_create_openreq_child  

	WARN_ON(child == NULL);

	sk_acceptq_removed(parent);//把源sock(也就是应用程序socket函数内核创建的sock的连接个数减1，因为取走了一个，就是上面的child)
	__reqsk_free(req);
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen;

	lopt->qlen_young++;
	lopt->qlen++;
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
    /*
	 * max_qlen_log是监听队列长度以2为底的对数，qlen是当前半连接请求块的数目。
	 * 如果移位之后为0，则表示监听队列还有空间，为1表示队列已满
	 */
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;
	req->retrans = 0;
	req->sk = NULL;
	req->dl_next = lopt->syn_table[hash];

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */

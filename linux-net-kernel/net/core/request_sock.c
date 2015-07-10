/*
 * NET		Generic infrastructure for Network protocols.
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

#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <net/request_sock.h>

/*
 * Maximum number of SYN_RECV sockets in queue per LISTEN socket.
 * One SYN_RECV socket costs about 80bytes on a 32bit machine.
 * It would be better to replace it with a global counter for all sockets
 * but then some measure against one socket starving all other sockets
 * would be needed.
 *
 * It was 128 by default. Experiments with real servers show, that
 * it is absolutely not enough even at 100conn/sec. 256 cures most
 * of problems. This value is adjusted to 128 for very small machines
 * (<=32Mb of memory) and to 1024 on normal or better ones (>=256Mb).
 * Note : Dont forget somaxconn that may limit backlog too.
 */
int sysctl_max_syn_backlog = 256;
/*
 * 用来分配连接请求块散列表，然后将其连接到所在传输控制块的请求
 * 块容器中。
 受以下几个参数影响: 见http://blog.chinaunix.net/uid-20662820-id-3776090.html
 （1）net.core.somaxconn
（2）net.ipv4.tcp_max_syn_backlog
（3）listen系统调用的backlog参数
 */
//开辟的空间大小是sizeof(struct listen_sock) + nr_table_entries * sizeof(struct request_sock *),所以syn_table指向后面的nr_table_entries * sizeof(struct request_sock *)部分，这只是hash表头的空间
int reqsk_queue_alloc(struct request_sock_queue *queue,
		      unsigned int nr_table_entries)
{
	size_t lopt_size = sizeof(struct listen_sock);
	struct listen_sock *lopt;

    /*
	 * 取用户设定的连接队列长度最大值参数nr_table_entries和系统最多
	 * 可同时存在未完成三次握手SYN请求数sysctl_max_syn_backlog两者的
	 * 最小值，他们都用来控制连接队列的长度，只是前者针对某传输控制
	 * 块，而后者控制的是全局的

	 这里可以看出listen_sock->max_qlen_log 为nr_table_entries和sysctl_max_syn_backlog的最小值加1
   并向上去整到2的次方后的log。
   比如： nr_table_entries = 128 sysctl_max_syn_backlog=20480，
               min(nr_table_entries, sysctl_max_syn_backlog)= 128
               roundup_pow_of_two(128+1)=256
               max_qlen_log=8
    */
	 
	nr_table_entries = min_t(u32, nr_table_entries, sysctl_max_syn_backlog);
	nr_table_entries = max_t(u32, nr_table_entries, 8);
	/*
	 * 调用roundup_pow_of_two以确保nr_table_entries的值为2的n次方
	 */
	nr_table_entries = roundup_pow_of_two(nr_table_entries + 1);
	/*
	 * 计算用来保存SYN请求连接的listen_sock结构的大小
	 */
	lopt_size += nr_table_entries * sizeof(struct request_sock *);//注意(struct request_sock *)是指针，空间大小为4
	if (lopt_size > PAGE_SIZE)
		lopt = __vmalloc(lopt_size,
			GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			PAGE_KERNEL);
	else
		lopt = kzalloc(lopt_size, GFP_KERNEL); 
	if (lopt == NULL)
		return -ENOMEM;
    //开辟的空间大小是sizeof(struct listen_sock) + nr_table_entries * sizeof(struct request_sock *),所以syn_table指向后面的nr_table_entries * sizeof(struct request_sock *)部分，这只是hash表头的空间
	for (lopt->max_qlen_log = 3;
	     (1 << lopt->max_qlen_log) < nr_table_entries;
	     lopt->max_qlen_log++);

	get_random_bytes(&lopt->hash_rnd, sizeof(lopt->hash_rnd));
	rwlock_init(&queue->syn_wait_lock);
	queue->rskq_accept_head = NULL;
	lopt->nr_table_entries = nr_table_entries;

	write_lock_bh(&queue->syn_wait_lock);
	queue->listen_opt = lopt; //queue->listen_opt指向request_sock
	write_unlock_bh(&queue->syn_wait_lock);

	return 0;
}

void __reqsk_queue_destroy(struct request_sock_queue *queue)
{
	struct listen_sock *lopt;
	size_t lopt_size;

	/*
	 * this is an error recovery path only
	 * no locking needed and the lopt is not NULL
	 */

	lopt = queue->listen_opt;
	lopt_size = sizeof(struct listen_sock) +
		lopt->nr_table_entries * sizeof(struct request_sock *);

	if (lopt_size > PAGE_SIZE)
		vfree(lopt);
	else
		kfree(lopt);
}

static inline struct listen_sock *reqsk_queue_yank_listen_sk(
		struct request_sock_queue *queue)
{
	struct listen_sock *lopt;

	write_lock_bh(&queue->syn_wait_lock);
	lopt = queue->listen_opt;
	queue->listen_opt = NULL;
	write_unlock_bh(&queue->syn_wait_lock);

	return lopt;
}

void reqsk_queue_destroy(struct request_sock_queue *queue)
{
	/* make all the listen_opt local to us */
	struct listen_sock *lopt = reqsk_queue_yank_listen_sk(queue);
	size_t lopt_size = sizeof(struct listen_sock) +
		lopt->nr_table_entries * sizeof(struct request_sock *);

	if (lopt->qlen != 0) {
		unsigned int i;

		for (i = 0; i < lopt->nr_table_entries; i++) {
			struct request_sock *req;

			while ((req = lopt->syn_table[i]) != NULL) {
				lopt->syn_table[i] = req->dl_next;
				lopt->qlen--;
				reqsk_free(req);
			}
		}
	}

	WARN_ON(lopt->qlen != 0);
	if (lopt_size > PAGE_SIZE)
		vfree(lopt);
	else
		kfree(lopt);
}


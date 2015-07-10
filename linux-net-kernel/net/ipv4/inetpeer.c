/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  This source is covered by the GNU GPL, the same as all kernel sources.
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <net/ip.h>
#include <net/inetpeer.h>

/*
 *  Theory of operations.
 *  We keep one entry for each peer IP address.  The nodes contains long-living
 *  information about the peer which doesn't depend on routes.
 *  At this moment this information consists only of ID field for the next
 *  outgoing IP packet.  This field is incremented with each packet as encoded
 *  in inet_getid() function (include/net/inetpeer.h).
 *  At the moment of writing this notes identifier of IP packets is generated
 *  to be unpredictable using this code only for packets subjected
 *  (actually or potentially) to defragmentation.  I.e. DF packets less than
 *  PMTU in size uses a constant ID and do not use this code (see
 *  ip_select_ident() in include/net/ip.h).
 *
 *  Route cache entries hold references to our nodes.
 *  New cache entries get references via lookup by destination IP address in
 *  the avl tree.  The reference is grabbed only when it's needed i.e. only
 *  when we try to output IP packet which needs an unpredictable ID (see
 *  __ip_select_ident() in net/ipv4/route.c).
 *  Nodes are removed only when reference counter goes to 0.
 *  When it's happened the node may be removed when a sufficient amount of
 *  time has been passed since its last use.  The less-recently-used entry can
 *  also be removed if the pool is overloaded i.e. if the total amount of
 *  entries is greater-or-equal than the threshold.
 *
 *  Node pool is organised as an AVL tree.
 *  Such an implementation has been chosen not just for fun.  It's a way to
 *  prevent easy and efficient DoS attacks by creating hash collisions.  A huge
 *  amount of long living nodes in a single hash slot would significantly delay
 *  lookups performed with disabled BHs.
 *
 *  Serialisation issues.
 *  1.  Nodes may appear in the tree only with the pool write lock held.
 *  2.  Nodes may disappear from the tree only with the pool write lock held
 *      AND reference count being 0.
 *  3.  Nodes appears and disappears from unused node list only under
 *      "inet_peer_unused_lock".
 *  4.  Global variable peer_total is modified under the pool lock.
 *  5.  struct inet_peer fields modification:
 *		avl_left, avl_right, avl_parent, avl_height: pool lock
 *		unused: unused node list lock
 *		refcnt: atomically against modifications on other CPU;
 *		   usually under some other lock to prevent node disappearing
 *		dtime: unused node list lock
 *		v4daddr: unchangeable
 *		ip_id_count: idlock
 */

static struct kmem_cache *peer_cachep __read_mostly;

#define node_height(x) x->avl_height
static struct inet_peer peer_fake_node = {
	.avl_left	= &peer_fake_node,
	.avl_right	= &peer_fake_node,
	.avl_height	= 0
};
#define peer_avl_empty (&peer_fake_node)
static struct inet_peer *peer_root = peer_avl_empty;
static DEFINE_RWLOCK(peer_pool_lock);
#define PEER_MAXDEPTH 40 /* sufficient for about 2^27 nodes */

static int peer_total;
/* Exported for sysctl_net_ipv4.  */
int inet_peer_threshold __read_mostly = 65536 + 128;	/* start to throw entries more
					 * aggressively at this stage */
int inet_peer_minttl __read_mostly = 120 * HZ;	/* TTL under high load: 120 sec */
int inet_peer_maxttl __read_mostly = 10 * 60 * HZ;	/* usual time to live: 10 min */
int inet_peer_gc_mintime __read_mostly = 10 * HZ;
int inet_peer_gc_maxtime __read_mostly = 120 * HZ;

static LIST_HEAD(unused_peers);
static DEFINE_SPINLOCK(inet_peer_unused_lock);

static void peer_check_expire(unsigned long dummy);
static DEFINE_TIMER(peer_periodic_timer, peer_check_expire, 0, 0);


/* Called from ip_output.c:ip_init  */
void __init inet_initpeers(void)
{
	struct sysinfo si;

	/* Use the straight interface to information about memory. */
	si_meminfo(&si);
	/* The values below were suggested by Alexey Kuznetsov
	 * <kuznet@ms2.inr.ac.ru>.  I don't have any opinion about the values
	 * myself.  --SAW
	 */
	if (si.totalram <= (32768*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 1; /* max pool size about 1MB on IA32 */
	if (si.totalram <= (16384*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 1; /* about 512KB */
	if (si.totalram <= (8192*1024)/PAGE_SIZE)
		inet_peer_threshold >>= 2; /* about 128KB */

	peer_cachep = kmem_cache_create("inet_peer_cache",
			sizeof(struct inet_peer),
			0, SLAB_HWCACHE_ALIGN|SLAB_PANIC,
			NULL);

	/* All the timers, started at system startup tend
	   to synchronize. Perturb it a bit.
	 */
	peer_periodic_timer.expires = jiffies
		+ net_random() % inet_peer_gc_maxtime
		+ inet_peer_gc_maxtime;
	add_timer(&peer_periodic_timer);
}

/* Called with or without local BH being disabled. */
static void unlink_from_unused(struct inet_peer *p)
{
	spin_lock_bh(&inet_peer_unused_lock);
	list_del_init(&p->unused);
	spin_unlock_bh(&inet_peer_unused_lock);
}

/*
 * Called with local BH disabled and the pool lock held.
 * _stack is known to be NULL or not at compile time,
 * so compiler will optimize the if (_stack) tests.
 */
#define lookup(_daddr, _stack) 					\
({								\
	struct inet_peer *u, **v;				\
	if (_stack != NULL) {					\
		stackptr = _stack;				\
		*stackptr++ = &peer_root;			\
	}							\
	for (u = peer_root; u != peer_avl_empty; ) {		\
		if (_daddr == u->v4daddr)			\
			break;					\
		if ((__force __u32)_daddr < (__force __u32)u->v4daddr)	\
			v = &u->avl_left;			\
		else						\
			v = &u->avl_right;			\
		if (_stack != NULL)				\
			*stackptr++ = v;			\
		u = *v;						\
	}							\
	u;							\
})

/* Called with local BH disabled and the pool write lock held. */
#define lookup_rightempty(start)				\
({								\
	struct inet_peer *u, **v;				\
	*stackptr++ = &start->avl_left;				\
	v = &start->avl_left;					\
	for (u = *v; u->avl_right != peer_avl_empty; ) {	\
		v = &u->avl_right;				\
		*stackptr++ = v;				\
		u = *v;						\
	}							\
	u;							\
})

/* Called with local BH disabled and the pool write lock held.
 * Variable names are the proof of operation correctness.
 * Look into mm/map_avl.c for more detail description of the ideas.  */
static void peer_avl_rebalance(struct inet_peer **stack[],
		struct inet_peer ***stackend)
{
	struct inet_peer **nodep, *node, *l, *r;
	int lh, rh;

	while (stackend > stack) {
		nodep = *--stackend;
		node = *nodep;
		l = node->avl_left;
		r = node->avl_right;
		lh = node_height(l);
		rh = node_height(r);
		if (lh > rh + 1) { /* l: RH+2 */
			struct inet_peer *ll, *lr, *lrl, *lrr;
			int lrh;
			ll = l->avl_left;
			lr = l->avl_right;
			lrh = node_height(lr);
			if (lrh <= node_height(ll)) {	/* ll: RH+1 */
				node->avl_left = lr;	/* lr: RH or RH+1 */
				node->avl_right = r;	/* r: RH */
				node->avl_height = lrh + 1; /* RH+1 or RH+2 */
				l->avl_left = ll;	/* ll: RH+1 */
				l->avl_right = node;	/* node: RH+1 or RH+2 */
				l->avl_height = node->avl_height + 1;
				*nodep = l;
			} else { /* ll: RH, lr: RH+1 */
				lrl = lr->avl_left;	/* lrl: RH or RH-1 */
				lrr = lr->avl_right;	/* lrr: RH or RH-1 */
				node->avl_left = lrr;	/* lrr: RH or RH-1 */
				node->avl_right = r;	/* r: RH */
				node->avl_height = rh + 1; /* node: RH+1 */
				l->avl_left = ll;	/* ll: RH */
				l->avl_right = lrl;	/* lrl: RH or RH-1 */
				l->avl_height = rh + 1;	/* l: RH+1 */
				lr->avl_left = l;	/* l: RH+1 */
				lr->avl_right = node;	/* node: RH+1 */
				lr->avl_height = rh + 2;
				*nodep = lr;
			}
		} else if (rh > lh + 1) { /* r: LH+2 */
			struct inet_peer *rr, *rl, *rlr, *rll;
			int rlh;
			rr = r->avl_right;
			rl = r->avl_left;
			rlh = node_height(rl);
			if (rlh <= node_height(rr)) {	/* rr: LH+1 */
				node->avl_right = rl;	/* rl: LH or LH+1 */
				node->avl_left = l;	/* l: LH */
				node->avl_height = rlh + 1; /* LH+1 or LH+2 */
				r->avl_right = rr;	/* rr: LH+1 */
				r->avl_left = node;	/* node: LH+1 or LH+2 */
				r->avl_height = node->avl_height + 1;
				*nodep = r;
			} else { /* rr: RH, rl: RH+1 */
				rlr = rl->avl_right;	/* rlr: LH or LH-1 */
				rll = rl->avl_left;	/* rll: LH or LH-1 */
				node->avl_right = rll;	/* rll: LH or LH-1 */
				node->avl_left = l;	/* l: LH */
				node->avl_height = lh + 1; /* node: LH+1 */
				r->avl_right = rr;	/* rr: LH */
				r->avl_left = rlr;	/* rlr: LH or LH-1 */
				r->avl_height = lh + 1;	/* r: LH+1 */
				rl->avl_right = r;	/* r: LH+1 */
				rl->avl_left = node;	/* node: LH+1 */
				rl->avl_height = lh + 2;
				*nodep = rl;
			}
		} else {
			node->avl_height = (lh > rh ? lh : rh) + 1;
		}
	}
}

/* Called with local BH disabled and the pool write lock held. */
#define link_to_pool(n)						\
do {								\
	n->avl_height = 1;					\
	n->avl_left = peer_avl_empty;				\
	n->avl_right = peer_avl_empty;				\
	**--stackptr = n;					\
	peer_avl_rebalance(stack, stackptr);			\
} while(0)

/* May be called with local BH enabled. */
static void unlink_from_pool(struct inet_peer *p)
{
	int do_free;

	do_free = 0;

	write_lock_bh(&peer_pool_lock);
	/* Check the reference counter.  It was artificially incremented by 1
	 * in cleanup() function to prevent sudden disappearing.  If the
	 * reference count is still 1 then the node is referenced only as `p'
	 * here and from the pool.  So under the exclusive pool lock it's safe
	 * to remove the node and free it later. */
	if (atomic_read(&p->refcnt) == 1) {
		struct inet_peer **stack[PEER_MAXDEPTH];
		struct inet_peer ***stackptr, ***delp;
		if (lookup(p->v4daddr, stack) != p)
			BUG();
		delp = stackptr - 1; /* *delp[0] == p */
		if (p->avl_left == peer_avl_empty) {
			*delp[0] = p->avl_right;
			--stackptr;
		} else {
			/* look for a node to insert instead of p */
			struct inet_peer *t;
			t = lookup_rightempty(p);
			BUG_ON(*stackptr[-1] != t);
			**--stackptr = t->avl_left;
			/* t is removed, t->v4daddr > x->v4daddr for any
			 * x in p->avl_left subtree.
			 * Put t in the old place of p. */
			*delp[0] = t;
			t->avl_left = p->avl_left;
			t->avl_right = p->avl_right;
			t->avl_height = p->avl_height;
			BUG_ON(delp[1] != &p->avl_left);
			delp[1] = &t->avl_left; /* was &p->avl_left */
		}
		peer_avl_rebalance(stack, stackptr);
		peer_total--;
		do_free = 1;
	}
	write_unlock_bh(&peer_pool_lock);

	if (do_free)
		kmem_cache_free(peer_cachep, p);
	else
		/* The node is used again.  Decrease the reference counter
		 * back.  The loop "cleanup -> unlink_from_unused
		 *   -> unlink_from_pool -> putpeer -> link_to_unused
		 *   -> cleanup (for the same node)"
		 * doesn't really exist because the entry will have a
		 * recent deletion time and will not be cleaned again soon. */
		inet_putpeer(p);
}

/* May be called with local BH enabled. */
/*
 * cleanup_once()用来检测inet_peer_unused_head队列中
 * 第一个闲置的对端信息块，一旦检测到
 * 该对端信息块闲置时间达到阈值，即将
 * 其释放。
 * @ttl:用来检测对端信息块闲置时间的阈值。
 */
static int cleanup_once(unsigned long ttl)
{
	struct inet_peer *p = NULL;

	/* Remove the first entry from the list of unused nodes. */
	spin_lock_bh(&inet_peer_unused_lock);
	/*
	 * 如果inet_peer_unused_head队列不为空，则获取
	 * 其上第一个闲置的对端信息块。检测该
	 * 对端信息块的闲置时间是否达到阈值。
	 * 如果达到，则将其从队列中摘除，否则
	 * 返回非0，表示没有对端信息块可释放。
	 */
	if (!list_empty(&unused_peers)) {
		__u32 delta;

		p = list_first_entry(&unused_peers, struct inet_peer, unused);
		delta = (__u32)jiffies - p->dtime;

		if (delta < ttl) {
			/* Do not prune fresh entries. */
			spin_unlock_bh(&inet_peer_unused_lock);
			return -1;
		}

		list_del_init(&p->unused);

		/* Grab an extra reference to prevent node disappearing
		 * before unlink_from_pool() call. */
		atomic_inc(&p->refcnt);
	}
	spin_unlock_bh(&inet_peer_unused_lock);

	/*
	 * 如果inet_peer_unused_head队列为空，则返回非0，表示
	 * 没有端信息块可释放。
	 */
	if (p == NULL)
		/* It means that the total number of USED entries has
		 * grown over inet_peer_threshold.  It shouldn't really
		 * happen because of entry limits in route cache. */
		return -1;

	/*
	 * 调用unlink_from_pool()将对端信息块从AVL
	 * 树中删除并释放。
	 */
	unlink_from_pool(p);
	/*
	 * 返回0，表示inet_peer_unused_head队列中可能
	 * 还有对端信息块可释放。
	 */
	return 0;
}


/* Called with or without local BH being disabled. */
/* Called with or without local BH being disabled. */
/*
 * 对端信息块的创建和查找都是通过inet_getpeer()来实现的，
 * 由参数create来区分是创建还是查找。首先检查指定地址
 * 的对端信息块，如果查找命中，则返回查找的结果，
 * 否则，当create为0时返回NULL，非0时创建新的对端
 * 信息块并添加到AVL树中，并返回该新创建的对端信息块。
 */ //
struct inet_peer *inet_getpeer(__be32 daddr, int create)//对端信息块的创建和查找
{
	struct inet_peer *p, *n;
	struct inet_peer **stack[PEER_MAXDEPTH], ***stackptr;

	/* Look up for the address quickly. */
	/*
	 * 根据地址在AVL树中查找对应的对端信息
	 * 块，如果查找命中，则增加对该对端
	 * 信息块的引用计数。
	 */
	read_lock_bh(&peer_pool_lock);
	p = lookup(daddr, NULL);
	if (p != peer_avl_empty)
		atomic_inc(&p->refcnt);
	read_unlock_bh(&peer_pool_lock);

	/*
	 * 如果查找到的对端信息块已经添加到
	 * inet_peer_unused_head队列上，则先将其删除，
	 * 以免被当作垃圾回收，然后返回查找
	 * 到的对端信息块。
	 */
	if (p != peer_avl_empty) {
		/* The existing node has been found. */
		/* Remove the entry from unused list if it was there. */
		unlink_from_unused(p);
		return p;
	}

	/*
	 * 如果根据地址没有找到相应的对端
	 * 信息块，且是查找操作，则返回NULL。
	 */
	if (!create)
		return NULL;

	/* Allocate the space outside the locked region. */
	/*
	 * 如果根据地址没找到相应的对端信息块，
	 * 且允许创建，则从高速缓存中分配对端
	 * 信息块，并设置相应的值。
	 */
	n = kmem_cache_alloc(peer_cachep, GFP_ATOMIC);
	if (n == NULL)
		return NULL;
	n->v4daddr = daddr;
	atomic_set(&n->refcnt, 1);
	atomic_set(&n->rid, 0);
	n->ip_id_count = secure_ip_id(daddr);
	n->tcp_ts_stamp = 0;

	/*
	 * 先检查是否有同样的地址的对端信息
	 * 块已添加到AVL树，因为在分配对端
	 * 信息块时，其他模块有可能已创建了
	 * 相同地址的对端信息块。如果有，则
	 * 不适用刚创建的对端信息块并将其释放。
	 * 如果没有，则将新创建的对端信息块
	 * 添加到AVL树并更新当前的对端信息块数。
	 */
	write_lock_bh(&peer_pool_lock);
	/* Check if an entry has suddenly appeared. */
	p = lookup(daddr, stack);
	if (p != peer_avl_empty)
		goto out_free;

	/* Link the node. */
	link_to_pool(n);
	INIT_LIST_HEAD(&n->unused);
	peer_total++;
	write_unlock_bh(&peer_pool_lock);

	/*
	 * 如果当前对端信息块数量超过了inet_peer_threshold，
	 * 则调用cleanup_once()释放inet_peer_unused_head队首的对端
	 * 信息块。
	 */
	if (peer_total >= inet_peer_threshold)
		/* Remove one less-recently-used entry. */
		cleanup_once(0);

	/*
	 * 返回创建的对端信息块。
	 */
	return n;

out_free:
	/*
	 * 在创建了对端信息块之后添加到AVL树时，有
	 * 其他模块创建了相同地址的对端信息块，
	 * 此时需要释放刚分配的对端信息块，而使用
	 * 其他模块已创建的对端信息块。
	 */
	/* The appropriate node is already in the pool. */
	atomic_inc(&p->refcnt);
	write_unlock_bh(&peer_pool_lock);
	/* Remove the entry from unused list if it was there. */
	unlink_from_unused(p);
	/* Free preallocated the preallocated node. */
	kmem_cache_free(peer_cachep, n);
	return p;
}


/* Called with local BH disabled. */
/*
 * peer_check_expire定时器的初始间隔时间在inet_initpeers()中
 * 设置，而在运行中，则会根据当前对端信息块
 * 的数量是否达到inet_peer_threshold，进行动态计算。
 * 因此，间隔时间与inet_peer_maxttl、inet_peer_minttl和
 * inet_peer_threshold有着密切的关系。
 */
static void peer_check_expire(unsigned long dummy)
{
	unsigned long now = jiffies;
	int ttl;

	/*
	 * 根据当前对端信息块数计算本次垃圾回收
	 * 的对端信息块生存期阈值。当前对端信息
	 * 块数大于inet_peer_threshold时，使用inet_peer_minttl
	 * 作为本次垃圾回收的对端信息块生存期
	 * 阈值，否则根据inet_peer_maxttl来计算本次垃圾
	 * 回收的对端信息块生存期阈值。
	 */
	if (peer_total >= inet_peer_threshold)
		ttl = inet_peer_minttl;
	else
		ttl = inet_peer_maxttl
				- (inet_peer_maxttl - inet_peer_minttl) / HZ *
					peer_total / inet_peer_threshold * HZ;
	/*
	 * 循环检测并删除闲置时间达到阈值
	 * 的对端信息块。
	 */
	while (!cleanup_once(ttl)) {
		if (jiffies != now)
			break;
	}

	/* Trigger the timer after inet_peer_gc_mintime .. inet_peer_gc_maxtime
	 * interval depending on the total number of entries (more entries,
	 * less interval). */
	/*
	 * 根据当前对端信息块数计算peer_check_expire定时器
	 * 下次激活时间，并重新设置该定时器。当前
	 * 对端信息块数大于inet_peer_threshold时，使用
	 * inet_peer_gc_mintime作为本次垃圾回收的时间间隔，
	 * 否则根据inet_peer_gc_maxtime来计算本次垃圾回收
	 * 的时间间隔。
	 */
	if (peer_total >= inet_peer_threshold)
		peer_periodic_timer.expires = jiffies + inet_peer_gc_mintime;
	else
		peer_periodic_timer.expires = jiffies
			+ inet_peer_gc_maxtime
			- (inet_peer_gc_maxtime - inet_peer_gc_mintime) / HZ *
				peer_total / inet_peer_threshold * HZ;
	add_timer(&peer_periodic_timer);
}

/*
 * 当使用完对端信息块之后，需要将其删除并释放。
 * 实际上，inet_putpeer()只是将该对端信息块添加到
 * unused_peers队列上，表示该对端信息块当前
 * 没有被使用。而真正的删除和释放，由垃圾
 * 回收机制来处理.
 */
void inet_putpeer(struct inet_peer *p)
{
	spin_lock_bh(&inet_peer_unused_lock);
	/*
	 * 当待删除的对端信息块的引用计数为0时,
	 * 表示没有被使用,此时将它添加到
	 * inet_peer_unused_head队列上,等待垃圾回收或
	 * 再次被使用.
	 */
	if (atomic_dec_and_test(&p->refcnt)) {
		list_add_tail(&p->unused, &unused_peers);
		p->dtime = (__u32)jiffies;
	}
	spin_unlock_bh(&inet_peer_unused_lock);
}


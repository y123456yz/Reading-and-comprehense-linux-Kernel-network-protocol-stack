/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic TIME_WAIT sockets functions
 *
 *		From code orinally in TCP
 */

#include <linux/kernel.h>
#include <linux/kmemcheck.h>
#include <linux/slab.h>
#include <net/inet_hashtables.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>


/**
 *	inet_twsk_unhash - unhash a timewait socket from established hash
 *	@tw: timewait socket
 *
 *	unhash a timewait socket from established hash, if hashed.
 *	ehash lock must be held by caller.
 *	Returns 1 if caller should call inet_twsk_put() after lock release.
 */
int inet_twsk_unhash(struct inet_timewait_sock *tw)
{
	if (hlist_nulls_unhashed(&tw->tw_node))
		return 0;

	hlist_nulls_del_rcu(&tw->tw_node);
	sk_nulls_node_init(&tw->tw_node);
	/*
	 * We cannot call inet_twsk_put() ourself under lock,
	 * caller must call it for us.
	 */
	return 1;
}

/**
 *	inet_twsk_bind_unhash - unhash a timewait socket from bind hash
 *	@tw: timewait socket
 *	@hashinfo: hashinfo pointer
 *
 *	unhash a timewait socket from bind hash, if hashed.
 *	bind hash lock must be held by caller.
 *	Returns 1 if caller should call inet_twsk_put() after lock release.
 */
int inet_twsk_bind_unhash(struct inet_timewait_sock *tw,
			  struct inet_hashinfo *hashinfo)
{
	struct inet_bind_bucket *tb = tw->tw_tb;

	if (!tb)
		return 0;

	__hlist_del(&tw->tw_bind_node);
	tw->tw_tb = NULL;
	inet_bind_bucket_destroy(hashinfo->bind_bucket_cachep, tb);
	/*
	 * We cannot call inet_twsk_put() ourself under lock,
	 * caller must call it for us.
	 */
	return 1;
}

/* Must be called with locally disabled BHs. */
static void __inet_twsk_kill(struct inet_timewait_sock *tw,
			     struct inet_hashinfo *hashinfo)
{
	struct inet_bind_hashbucket *bhead;
	int refcnt;
	/* Unlink from established hashes. */
	spinlock_t *lock = inet_ehash_lockp(hashinfo, tw->tw_hash);

	spin_lock(lock);
	refcnt = inet_twsk_unhash(tw);
	spin_unlock(lock);

	/* Disassociate with bind bucket. */
	bhead = &hashinfo->bhash[inet_bhashfn(twsk_net(tw), tw->tw_num,
			hashinfo->bhash_size)];

	spin_lock(&bhead->lock);
	refcnt += inet_twsk_bind_unhash(tw, hashinfo);
	spin_unlock(&bhead->lock);

#ifdef SOCK_REFCNT_DEBUG
	if (atomic_read(&tw->tw_refcnt) != 1) {
		printk(KERN_DEBUG "%s timewait_sock %p refcnt=%d\n",
		       tw->tw_prot->name, tw, atomic_read(&tw->tw_refcnt));
	}
#endif
	while (refcnt) {
		inet_twsk_put(tw);
		refcnt--;
	}
}

static noinline void inet_twsk_free(struct inet_timewait_sock *tw)
{
	struct module *owner = tw->tw_prot->owner;
	twsk_destructor((struct sock *)tw);
#ifdef SOCK_REFCNT_DEBUG
	pr_debug("%s timewait_sock %p released\n", tw->tw_prot->name, tw);
#endif
	release_net(twsk_net(tw));
	kmem_cache_free(tw->tw_prot->twsk_prot->twsk_slab, tw);
	module_put(owner);
}

void inet_twsk_put(struct inet_timewait_sock *tw)
{
	if (atomic_dec_and_test(&tw->tw_refcnt))
		inet_twsk_free(tw);
}
EXPORT_SYMBOL_GPL(inet_twsk_put);

/*
 * Enter the time wait state. This is called with locally disabled BH.
 * Essentially we whip up a timewait bucket, copy the relevant info into it
 * from the SK, and mess with hash chains and list linkage.
 *//*
 * 将timewait控制块添加到tcp_hashinfo的ebash散列表中，
 * 将被替代的TCP控制块从ehash散列表中删除。这样
 * FIN_WAIT2和TIME_WAIT状态下也可以进行输入的处理。
 * 同时将该timewait控制块添加到bhash散列表中，但
 * 并不删除该散列表中被替代的TCP控制块，因为
 * 只要inet->num不为0，这个绑定关系就存在，
 * 即使该套接字已经关闭
 */
void __inet_twsk_hashdance(struct inet_timewait_sock *tw, struct sock *sk,
			   struct inet_hashinfo *hashinfo)
{
	const struct inet_sock *inet = inet_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_ehash_bucket *ehead = inet_ehash_bucket(hashinfo, sk->sk_hash);
	spinlock_t *lock = inet_ehash_lockp(hashinfo, sk->sk_hash);
	struct inet_bind_hashbucket *bhead;
	/* Step 1: Put TW into bind hash. Original socket stays there too.
	   Note, that any socket with inet->num != 0 MUST be bound in
	   binding cache, even if it is closed.
	 */
	bhead = &hashinfo->bhash[inet_bhashfn(twsk_net(tw), inet->inet_num,
			hashinfo->bhash_size)];
	spin_lock(&bhead->lock);
	tw->tw_tb = icsk->icsk_bind_hash;
	WARN_ON(!icsk->icsk_bind_hash);

	//将inet_timewait_sock添加到
	inet_twsk_add_bind_node(tw, &tw->tw_tb->owners);//讲inet_bind_bucket桶指向tw->tw_bind_node，避免该函数外面在释放sk的时候，会释放掉bind桶信息
	spin_unlock(&bhead->lock);

	spin_lock(lock);

	/*
	 * Step 2: Hash TW into TIMEWAIT chain.
	 * Should be done before removing sk from established chain
	 * because readers are lockless and search established first.
	 */
	inet_twsk_add_node_rcu(tw, &ehead->twchain);//把新创建的inet_timewait_sock加入到inet_hash中的ehash中

	/* Step 3: Remove SK from established hash. */
	if (__sk_nulls_del_node_init_rcu(sk))//把sk从inet_hash中的ehash表中删除
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

	/*
	 * Notes :
	 * - We initially set tw_refcnt to 0 in inet_twsk_alloc()
	 * - We add one reference for the bhash link
	 * - We add one reference for the ehash link
	 * - We want this refcnt update done before allowing other
	 *   threads to find this tw in ehash chain.
	 */
	atomic_add(1 + 1 + 1, &tw->tw_refcnt);

	spin_unlock(lock);
}
EXPORT_SYMBOL_GPL(__inet_twsk_hashdance);

struct inet_timewait_sock *inet_twsk_alloc(const struct sock *sk, const int state)
{
	struct inet_timewait_sock *tw =
		kmem_cache_alloc(sk->sk_prot_creator->twsk_prot->twsk_slab,
				 GFP_ATOMIC);
	if (tw != NULL) {
		const struct inet_sock *inet = inet_sk(sk);

		kmemcheck_annotate_bitfield(tw, flags);

		/* Give us an identity. */
		tw->tw_daddr	    = inet->inet_daddr;
		tw->tw_rcv_saddr    = inet->inet_rcv_saddr;
		tw->tw_bound_dev_if = sk->sk_bound_dev_if;
		tw->tw_num	    = inet->inet_num;
		tw->tw_state	    = TCP_TIME_WAIT;
		tw->tw_substate	    = state;
		tw->tw_sport	    = inet->inet_sport;
		tw->tw_dport	    = inet->inet_dport;
		tw->tw_family	    = sk->sk_family;
		tw->tw_reuse	    = sk->sk_reuse;
		tw->tw_hash	    = sk->sk_hash;
		tw->tw_ipv6only	    = 0;
		tw->tw_transparent  = inet->transparent;
		tw->tw_prot	    = sk->sk_prot_creator;
		twsk_net_set(tw, hold_net(sock_net(sk)));
		/*
		 * Because we use RCU lookups, we should not set tw_refcnt
		 * to a non null value before everything is setup for this
		 * timewait socket.
		 */
		atomic_set(&tw->tw_refcnt, 0);
		inet_twsk_dead_node_init(tw);
		__module_get(tw->tw_prot->owner);
	}

	return tw;
}
EXPORT_SYMBOL_GPL(inet_twsk_alloc);

/* Returns non-zero if quota exceeded.  */
/*
 * 删除cells散列表中当前关键字链表上的timewait控制块。
 * 如果在inet_twdr_do_twkill_work()清理的timewait控制块数超过
 * 100个，则说明还有一定量的timewait控制块需要处理。
 * 而在定时器例程中处理，长时间不返回，会影响
 * 系统性能，因此剩下的timewait控制块放在twkill_work
 * 工作队列中处理。调度twkill_work工作队列前，先标识
 * 待删除slot的位图，这样在twkill_work工作队列处理中，
 * 根据thread_slots位图，处理cells散列表中相应的链表。
 * inet_twdr_do_twkill_work()用来删除指定cells散列表中slot入口
 * 链表中slot入口链表上的timewait控制块，然后将其释放，
 * 最后更新系统中timewait控制块数。在删除过程中，
 * 如果本次删除的个数达到100，则返回非零，表示
 * 调用者需中断本次处理，重新调度。
 */
static int inet_twdr_do_twkill_work(struct inet_timewait_death_row *twdr,
				    const int slot)
{
	struct inet_timewait_sock *tw;
	struct hlist_node *node;
	unsigned int killed;
	int ret;

	/* NOTE: compare this to previous version where lock
	 * was released after detaching chain. It was racy,
	 * because tw buckets are scheduled in not serialized context
	 * in 2.3 (with netfilter), and with softnet it is common, because
	 * soft irqs are not sequenced.
	 */
	killed = 0;
	ret = 0;
rescan:
	inet_twsk_for_each_inmate(tw, node, &twdr->cells[slot]) {
		__inet_twsk_del_dead_node(tw);
		spin_unlock(&twdr->death_lock);
		__inet_twsk_kill(tw, twdr->hashinfo);
#ifdef CONFIG_NET_NS
		NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_TIMEWAITED);
#endif
		inet_twsk_put(tw);
		killed++;
		spin_lock(&twdr->death_lock);
		if (killed > INET_TWDR_TWKILL_QUOTA) {
			ret = 1;
			break;
		}

		/* While we dropped twdr->death_lock, another cpu may have
		 * killed off the next TW bucket in the list, therefore
		 * do a fresh re-read of the hlist head node with the
		 * lock reacquired.  We still use the hlist traversal
		 * macro in order to get the prefetches.
		 */
		goto rescan;
	}

	twdr->tw_count -= killed;
#ifndef CONFIG_NET_NS
	NET_ADD_STATS_BH(&init_net, LINUX_MIB_TIMEWAITED, killed);
#endif
	return ret;
}

/*
 * tw_timer定时器的例程，该定时器超时后，会
 * 遍历twcal_row散列表中当前关键字slot链表上的
 * timewait控制块。
 */
void inet_twdr_hangman(unsigned long data)
{
	struct inet_timewait_death_row *twdr;
	int unsigned need_timer;

	twdr = (struct inet_timewait_death_row *)data;
	spin_lock(&twdr->death_lock);

	/*
	 * 如果当前timewait控制块数为零，则无需
	 * 再做处理了。
	 */
	if (twdr->tw_count == 0)
		goto out;

	/*
	 * 删除cells散列表中当前关键字链表上的timewait控制块。
	 * 如果在inet_twdr_do_twkill_work()清理的timewait控制块数超过
	 * 100个，则说明还有一定量的timewait控制块需要处理。
	 * 而在定时器例程中处理，长时间不返回，会影响
	 * 系统性能，因此剩下的timewait控制块放在twkill_work
	 * 工作队列中处理。调度twkill_work工作队列前，先标识
	 * 待删除slot的位图，这样在twkill_work工作队列处理中，
	 * 根据thread_slots位图，处理cells散列表中相应的链表。
	 * inet_twdr_do_twkill_work()用来删除指定cells散列表中slot入口
	 * 链表中slot入口链表上的timewait控制块，然后将其释放，
	 * 最后更新系统中timewait控制块数。在删除过程中，
	 * 如果本次删除的个数达到100，则返回非零，表示
	 * 调用者需中断本次处理，重新调度。
	 */
	need_timer = 0;
	if (inet_twdr_do_twkill_work(twdr, twdr->slot)) {//第一个tw_timer超时的时候，twdr->slot=0,低二个tw_timer超时的时候，该值变1，当到7后又回到1，也就保证了cells中的所有timewait被遍历到
		twdr->thread_slots |= (1 << twdr->slot);
		schedule_work(&twdr->twkill_work);
		need_timer = 1;
	} else {
		/* We purged the entire slot, anything left?  */
		/*
		 * 如果还有timewait控制块，则还需设置定时器。
		 */
		if (twdr->tw_count)
			need_timer = 1;
		/*
		 * 本次超时处理完成后，需设置下次超时处理的
		 * cells散列表入口。
		 */
		twdr->slot = ((twdr->slot + 1) & (INET_TWDR_TWKILL_SLOTS - 1));
	}
	/*
	 * 如果还有timewait控制块需处理，则再次设置定时器。
	 */
	if (need_timer)
		mod_timer(&twdr->tw_timer, jiffies + twdr->period);
out:
	spin_unlock(&twdr->death_lock);
}

void inet_twdr_hangman1(unsigned long data)
{
	struct inet_timewait_death_row *twdr;
	int unsigned need_timer;

	twdr = (struct inet_timewait_death_row *)data;
	spin_lock(&twdr->death_lock);

	if (twdr->tw_count == 0)
		goto out;

	need_timer = 0;
	if (inet_twdr_do_twkill_work(twdr, twdr->slot)) {
		twdr->thread_slots |= (1 << twdr->slot);
		schedule_work(&twdr->twkill_work);
		need_timer = 1;
	} else {
		/* We purged the entire slot, anything left?  */
		if (twdr->tw_count)
			need_timer = 1;
		twdr->slot = ((twdr->slot + 1) & (INET_TWDR_TWKILL_SLOTS - 1));
	}
	if (need_timer)
		mod_timer(&twdr->tw_timer, jiffies + twdr->period);
out:
	spin_unlock(&twdr->death_lock);
}
EXPORT_SYMBOL_GPL(inet_twdr_hangman);

/*
 * twkill_work工作队列的例程，当tw_timer定时器例程中处理
 * 的timewait控制块达到100个时，会调度twkill_work工作队列，
 * 清理剩下的timewait控制块。
 * 处理时会根据待删除slot的位图，删除对应slot链表上的
 * timewait控制块，在twkill_work工作队列例程中每处理100个
 * timewait控制块暂时睡眠，然后再次处理，直至全部处理
 * 完成。
 */
void inet_twdr_twkill_work(struct work_struct *work)
{
	struct inet_timewait_death_row *twdr =
		container_of(work, struct inet_timewait_death_row, twkill_work);
	int i;

	BUILD_BUG_ON((INET_TWDR_TWKILL_SLOTS - 1) >
			(sizeof(twdr->thread_slots) * 8));

	while (twdr->thread_slots) {
		spin_lock_bh(&twdr->death_lock);
		for (i = 0; i < INET_TWDR_TWKILL_SLOTS; i++) {
			if (!(twdr->thread_slots & (1 << i)))
				continue;

			while (inet_twdr_do_twkill_work(twdr, i) != 0) {
				if (need_resched()) {
					spin_unlock_bh(&twdr->death_lock);
					schedule();
					spin_lock_bh(&twdr->death_lock);
				}
			}

			twdr->thread_slots &= ~(1 << i);
		}
		spin_unlock_bh(&twdr->death_lock);
	}
}
EXPORT_SYMBOL_GPL(inet_twdr_twkill_work);

/* These are always called from BH context.  See callers in
 * tcp_input.c to verify this.
 */

/* This is for handling early-kills of TIME_WAIT sockets. */
void inet_twsk_deschedule(struct inet_timewait_sock *tw,
			  struct inet_timewait_death_row *twdr)
{
	spin_lock(&twdr->death_lock);
	if (inet_twsk_del_dead_node(tw)) {
		inet_twsk_put(tw);
		if (--twdr->tw_count == 0)
			del_timer(&twdr->tw_timer);
	}
	spin_unlock(&twdr->death_lock);
	__inet_twsk_kill(tw, twdr->hashinfo);
}
EXPORT_SYMBOL(inet_twsk_deschedule);

/*
 * 用于启动FIN_WAIT_2或TIME_WAIT定时器。虽然
 * 启动这两个定时器用的是同一个接口，但是
 * 根据timewait控制块的tw_substate很明确地区别
 * 当前启动的是哪个定时器
 * @tw: 已经替代TCP传输控制块的timewait控制块
 * @twdr: 管理相关的数据的容器，通常传入全局
 *             变量tcp_death_row。
 * @timeo: 设定定时器的超时时间
 * @timewait_len: 超时时间上限，为TCP_TIMEWAIT_LEN。
 */
void inet_twsk_schedule(struct inet_timewait_sock *tw,
		       struct inet_timewait_death_row *twdr,
		       const int timeo, const int timewait_len)
{
	struct hlist_head *list;
	int slot;

	/*
	 * RTO是超时重传时间(Retransmission timeout)的意思。
	 * 计时器的RTO应略大于RTT(平均往返时间，
	 * Round-Trip Time)
        * 即：RTO＝b*RTT
        * 这里b是个大于1的系数。
        * 若取b很接近于1，发送端可及时地重传丢失
        * 的报文段，因此效率得到提高。
        * 但若报文段并未丢失而仅仅是增加了一点时延,
        * 那么过早地重传反而会加重网络的负担。
        * 因此TCP原先的标准推荐将b值取为2。
	 */
	 /*
	 * 在重传情况下，重传超时时间采用一种称为
	 * “指数退避”的方式计算。例如：当重传超
	 * 时时间为1S的情况下发生了数据重传，我们
	 * 就用重传超时时间为2S的定时器来重传数据，
	 * 下一次用4S，一直增加到64S为止（参见tcp_retransmit_timer（））。
	 * 所以这里的RTO*3.5=RTO*0.5+RTO*1+RTO*2,其中RTO*0.5是
	 * 第一次发送ACK的时间到对端的超时时间（系
	 * 数就是乘以RTO的值），RTO*1是对端第一次重传FIN
	 * 包到ACK包到达对端的超时时间，RTO*2是对端第
	 * 二次重传FIN包到ACK包到达对端的超时时间。注意
	 * ，重传超时时间的指数退避操作（就是乘以2）是在
	 * 重传之后执行的，所以第一次重传的超时时间和
	 * 第一次发送的超时时间相同。
	 */
	/* timeout := RTO * 3.5
	 *
	 * 3.5 = 1+2+0.5 to wait for two retransmits.
	 *
	 * RATIONALE: if FIN arrived and we entered TIME-WAIT state,
	 * our ACK acking that FIN can be lost. If N subsequent retransmitted
	 * FINs (or previous seqments) are lost (probability of such event
	 * is p^(N+1), where p is probability to lose single packet and
	 * time to detect the loss is about RTO*(2^N - 1) with exponential
	 * backoff). Normal timewait length is calculated so, that we
	 * waited at least for one retransmitted FIN (maximal RTO is 120sec).
	 * [ BTW Linux. following BSD, violates this requirement waiting
	 *   only for 60sec, we should wait at least for 240 secs.
	 *   Well, 240 consumes too much of resources 8)
	 * ]
	 * This interval is not reduced to catch old duplicate and
	 * responses to our wandering segments living for two MSLs.
	 * However, if we use PAWS to detect
	 * old duplicates, we can reduce the interval to bounds required
	 * by RTO, rather than MSL. So, if peer understands PAWS, we
	 * kill tw bucket after 3.5*RTO (it is important that this number
	 * is greater than TS tick!) and detect old duplicates with help
	 * of PAWS.
	 */
	/*
	 * TIME_WAIT超时时间除以INET_TWDR_RECYCLE_TICK后
	 * 向上取整，用来判断将该timewait控制块添加
	 * 到cells还是twcal_row散列表中。
	 * 如果得到值大于或等于INET_TWDR_RECYCLE_SLOTS，
	 * 则将其添加到cells散列表中，否则添加到
	 * twcal_row散列表中
	 */
	slot = (timeo + (1 << INET_TWDR_RECYCLE_TICK) - 1) >> INET_TWDR_RECYCLE_TICK;

	spin_lock(&twdr->death_lock);

	/* Unlink it, if it was scheduled */
	/*
	 * 如果该timewait控制块已经被调度，从散列表中摘除，
	 * 并需要递减当前系统中处于TIME_wAIT状态的套接字数
	 */
	if (inet_twsk_del_dead_node(tw)) 
		twdr->tw_count--; //在该函数inet_twsk_schedule外面的inet_twsk_put中是否timewait空间
	else
		atomic_inc(&tw->tw_refcnt);

	if (slot >= INET_TWDR_RECYCLE_SLOTS) { //这里的slot是根据定时器超时时间timeo来的，所以就相当于根据超时时间把timewait散列到cells表中。
	/*
	 * 准备添加到cells散列表中。设置timewait控制块
	 * 超时删除时间，并计算添加到cells散列表的
	 * 哪个桶中
	 */
		/* Schedule to slow timer */
		if (timeo >= timewait_len) {
			slot = INET_TWDR_TWKILL_SLOTS - 1;
		} else {
			slot = DIV_ROUND_UP(timeo, twdr->period);//这个相当于是计算timeo是twdr->period的几倍，也就是几个TCP_TIMEWAIT_LEN / INET_TWDR_TWKILL_SLOTS
			if (slot >= INET_TWDR_TWKILL_SLOTS) //这样就可以按照时间散列到cell中，表示有多少个slot个TCP_TIMEWAIT_LEN / INET_TWDR_TWKILL_SLOTS
				slot = INET_TWDR_TWKILL_SLOTS - 1;
		}
		tw->tw_ttd = jiffies + timeo;
		slot = (twdr->slot + slot) & (INET_TWDR_TWKILL_SLOTS - 1);
		list = &twdr->cells[slot];
	} else {
		/*
		 * 准备添加到twcal_row散列表中。如果twcal_row
		 * 散列表为空，则先设置下次超时时处理的
		 * 桶，然后设置超时时间后启动定时器。
		 * 如果twcal_row散列表不为空，且本次超时时间
		 * 遭遇该定时器的超时时间，则需重新设置
		 * 定时器的超时时间。
		 * 最后获取添加到twcal_row散列表的哪个桶
		 */
		tw->tw_ttd = jiffies + (slot << INET_TWDR_RECYCLE_TICK);

		if (twdr->twcal_hand < 0) {
			twdr->twcal_hand = 0;
			twdr->twcal_jiffie = jiffies;
			twdr->twcal_timer.expires = twdr->twcal_jiffie +
					      (slot << INET_TWDR_RECYCLE_TICK);
			add_timer(&twdr->twcal_timer);
		} else {
			if (time_after(twdr->twcal_timer.expires,
				       jiffies + (slot << INET_TWDR_RECYCLE_TICK)))
				mod_timer(&twdr->twcal_timer,
					  jiffies + (slot << INET_TWDR_RECYCLE_TICK));
			slot = (twdr->twcal_hand + slot) & (INET_TWDR_RECYCLE_SLOTS - 1);
		}
		list = &twdr->twcal_row[slot];
	}

	/*
	 * 将timewait控制块添加到相应的散列表中。
	 */
	hlist_add_head(&tw->tw_death_node, list);

	/*
	 * 如果系统之前不存在timewait控制块，
	 * 则需设定tw_timer定时器。
	 */ //inet_twdr_hangman 
	if (twdr->tw_count++ == 0)  //真正的timewait控制块在这里面删除        tw_timer定时器回调函数是inet_twdr_hangman
		mod_timer(&twdr->tw_timer, jiffies + twdr->period);//注意，这个是tcp_death_row里面的定时器，需要一直运行着,注意和inet_csk_init_xmit_timers中几种定时器的区别
	spin_unlock(&twdr->death_lock);
}

void inet_twsk_schedule1(struct inet_timewait_sock *tw,
		       struct inet_timewait_death_row *twdr,
		       const int timeo, const int timewait_len)
{
	struct hlist_head *list;
	int slot;

	/* timeout := RTO * 3.5
	 *
	 * 3.5 = 1+2+0.5 to wait for two retransmits.
	 *
	 * RATIONALE: if FIN arrived and we entered TIME-WAIT state,
	 * our ACK acking that FIN can be lost. If N subsequent retransmitted
	 * FINs (or previous seqments) are lost (probability of such event
	 * is p^(N+1), where p is probability to lose single packet and
	 * time to detect the loss is about RTO*(2^N - 1) with exponential
	 * backoff). Normal timewait length is calculated so, that we
	 * waited at least for one retransmitted FIN (maximal RTO is 120sec).
	 * [ BTW Linux. following BSD, violates this requirement waiting
	 *   only for 60sec, we should wait at least for 240 secs.
	 *   Well, 240 consumes too much of resources 8)
	 * ]
	 * This interval is not reduced to catch old duplicate and
	 * responces to our wandering segments living for two MSLs.
	 * However, if we use PAWS to detect
	 * old duplicates, we can reduce the interval to bounds required
	 * by RTO, rather than MSL. So, if peer understands PAWS, we
	 * kill tw bucket after 3.5*RTO (it is important that this number
	 * is greater than TS tick!) and detect old duplicates with help
	 * of PAWS.
	 */
	slot = (timeo + (1 << INET_TWDR_RECYCLE_TICK) - 1) >> INET_TWDR_RECYCLE_TICK;

	spin_lock(&twdr->death_lock);

	/* Unlink it, if it was scheduled */
	if (inet_twsk_del_dead_node(tw))
		twdr->tw_count--;
	else
		atomic_inc(&tw->tw_refcnt);

	if (slot >= INET_TWDR_RECYCLE_SLOTS) {
		/* Schedule to slow timer */
		if (timeo >= timewait_len) {
			slot = INET_TWDR_TWKILL_SLOTS - 1;
		} else {
			slot = DIV_ROUND_UP(timeo, twdr->period);
			if (slot >= INET_TWDR_TWKILL_SLOTS)
				slot = INET_TWDR_TWKILL_SLOTS - 1;
		}
		tw->tw_ttd = jiffies + timeo;
		slot = (twdr->slot + slot) & (INET_TWDR_TWKILL_SLOTS - 1);
		list = &twdr->cells[slot];
	} else {
		tw->tw_ttd = jiffies + (slot << INET_TWDR_RECYCLE_TICK);

		if (twdr->twcal_hand < 0) {
			twdr->twcal_hand = 0;
			twdr->twcal_jiffie = jiffies;
			twdr->twcal_timer.expires = twdr->twcal_jiffie +
					      (slot << INET_TWDR_RECYCLE_TICK);
			add_timer(&twdr->twcal_timer);
		} else {
			if (time_after(twdr->twcal_timer.expires,
				       jiffies + (slot << INET_TWDR_RECYCLE_TICK)))
				mod_timer(&twdr->twcal_timer,
					  jiffies + (slot << INET_TWDR_RECYCLE_TICK));
			slot = (twdr->twcal_hand + slot) & (INET_TWDR_RECYCLE_SLOTS - 1);
		}
		list = &twdr->twcal_row[slot];
	}

	hlist_add_head(&tw->tw_death_node, list);

	if (twdr->tw_count++ == 0)
		mod_timer(&twdr->tw_timer, jiffies + twdr->period);
	spin_unlock(&twdr->death_lock);
}
EXPORT_SYMBOL_GPL(inet_twsk_schedule);

/*
 * twcal_timer定时器的例程，该定时器超时后，
 * 会遍历twcal_row散列表，清除其中已超时
 * 的timewait控制块
 */
void inet_twdr_twcal_tick(unsigned long data)
{
	struct inet_timewait_death_row *twdr;
	int n, slot;
	unsigned long j;
	unsigned long now = jiffies;
	int killed = 0;
	int adv = 0;

	twdr = (struct inet_timewait_death_row *)data;

	spin_lock(&twdr->death_lock);
	/*
	 * twcal_hand小于0，表示twcal_row散列表中不存在
	 * timewait控制块，因此在遍历之前需先校验。
	 */
	if (twdr->twcal_hand < 0)
		goto out;

	/*
	 * 获取本次遍历twcal_row散列表的入口。同时
	 * 取得该散列表入口队列上的超时时间，
	 * 用于检测timewait控制块是否已超时
	 */
	slot = twdr->twcal_hand;
	j = twdr->twcal_jiffie;

	/*
	 * 遍历twcal_row散列表，删除已超时的timewait控制块
	 */
	for (n = 0; n < INET_TWDR_RECYCLE_SLOTS; n++) {
		/*
		 * 如果当前入口链表中的timewait控制块已超时，
		 * 则将其从twcal_row以及bhash、ehash散列表中删除，
		 * 然后将其释放，最后统计本次删除释放的
		 * timewait控制块数。
		 */
		if (time_before_eq(j, now)) {
			struct hlist_node *node, *safe;
			struct inet_timewait_sock *tw;

			inet_twsk_for_each_inmate_safe(tw, node, safe,
						       &twdr->twcal_row[slot]) {
				__inet_twsk_del_dead_node(tw);
				__inet_twsk_kill(tw, twdr->hashinfo);
#ifdef CONFIG_NET_NS
				NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_TIMEWAITKILLED);
#endif
				inet_twsk_put(tw);
				killed++;
			}
		} else {
			/*
			 * 当遍历到超时时间小于当前超时时间内，说明
			 * 超时的timewait控制块已全部处理完成，可以设置
			 * 下一次超时的twcal_jiffie和入口twcal_hand。然后在剩下
			 * 的散列表中查找是否还有未超时的timewait控制块，
			 * 如果有则重新设置超时时间后返回，否则说明
			 * 所有的timewait控制块都已清除，需将twcal_hand设置为-1.
			 */
			if (!adv) {
				adv = 1;
				twdr->twcal_jiffie = j;
				twdr->twcal_hand = slot;
			}

			if (!hlist_empty(&twdr->twcal_row[slot])) {
				mod_timer(&twdr->twcal_timer, j);
				goto out;
			}
		}
		/*
		 * 在遍历timewait控制块时，需要入口的关键字
		 * 及入口链表上的超时时间。
		 */
		j += 1 << INET_TWDR_RECYCLE_TICK;
		slot = (slot + 1) & (INET_TWDR_RECYCLE_SLOTS - 1);
	}
	twdr->twcal_hand = -1;

/*
 * 如果当前系统timewait控制块数为零，则
 * 停止tw_timer定时器。
 */
out:
	if ((twdr->tw_count -= killed) == 0)
		del_timer(&twdr->tw_timer);
#ifndef CONFIG_NET_NS
	NET_ADD_STATS_BH(&init_net, LINUX_MIB_TIMEWAITKILLED, killed);
#endif
	spin_unlock(&twdr->death_lock);
}

void inet_twdr_twcal_tick1(unsigned long data)
{
	struct inet_timewait_death_row *twdr;
	int n, slot;
	unsigned long j;
	unsigned long now = jiffies;
	int killed = 0;
	int adv = 0;

	twdr = (struct inet_timewait_death_row *)data;

	spin_lock(&twdr->death_lock);
	if (twdr->twcal_hand < 0)
		goto out;

	slot = twdr->twcal_hand;
	j = twdr->twcal_jiffie;

	for (n = 0; n < INET_TWDR_RECYCLE_SLOTS; n++) {
		if (time_before_eq(j, now)) {
			struct hlist_node *node, *safe;
			struct inet_timewait_sock *tw;

			inet_twsk_for_each_inmate_safe(tw, node, safe,
						       &twdr->twcal_row[slot]) {
				__inet_twsk_del_dead_node(tw);
				__inet_twsk_kill(tw, twdr->hashinfo);
#ifdef CONFIG_NET_NS
				NET_INC_STATS_BH(twsk_net(tw), LINUX_MIB_TIMEWAITKILLED);
#endif
				inet_twsk_put(tw);
				killed++;
			}
		} else {
			if (!adv) {
				adv = 1;
				twdr->twcal_jiffie = j;
				twdr->twcal_hand = slot;
			}

			if (!hlist_empty(&twdr->twcal_row[slot])) {
				mod_timer(&twdr->twcal_timer, j);
				goto out;
			}
		}
		j += 1 << INET_TWDR_RECYCLE_TICK;
		slot = (slot + 1) & (INET_TWDR_RECYCLE_SLOTS - 1);
	}
	twdr->twcal_hand = -1;

out:
	if ((twdr->tw_count -= killed) == 0)
		del_timer(&twdr->tw_timer);
#ifndef CONFIG_NET_NS
	NET_ADD_STATS_BH(&init_net, LINUX_MIB_TIMEWAITKILLED, killed);
#endif
	spin_unlock(&twdr->death_lock);
}
EXPORT_SYMBOL_GPL(inet_twdr_twcal_tick);

void inet_twsk_purge(struct inet_hashinfo *hashinfo,
		     struct inet_timewait_death_row *twdr, int family)
{
	struct inet_timewait_sock *tw;
	struct sock *sk;
	struct hlist_nulls_node *node;
	unsigned int slot;

	for (slot = 0; slot <= hashinfo->ehash_mask; slot++) {
		struct inet_ehash_bucket *head = &hashinfo->ehash[slot];
restart_rcu:
		rcu_read_lock();
restart:
		sk_nulls_for_each_rcu(sk, node, &head->twchain) {
			tw = inet_twsk(sk);
			if ((tw->tw_family != family) ||
				atomic_read(&twsk_net(tw)->count))
				continue;

			if (unlikely(!atomic_inc_not_zero(&tw->tw_refcnt)))
				continue;

			if (unlikely((tw->tw_family != family) ||
				     atomic_read(&twsk_net(tw)->count))) {
				inet_twsk_put(tw);
				goto restart;
			}

			rcu_read_unlock();
			inet_twsk_deschedule(tw, twdr);
			inet_twsk_put(tw);
			goto restart_rcu;
		}
		/* If the nulls value we got at the end of this lookup is
		 * not the expected one, we must restart lookup.
		 * We probably met an item that was moved to another chain.
		 */
		if (get_nulls_value(node) != slot)
			goto restart;
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL_GPL(inet_twsk_purge);

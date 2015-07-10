/*
 *	Routines having to do with the 'struct sk_buff' memory handlers.
 *
 *	Authors:	Alan Cox <alan@lxorguk.ukuu.org.uk>
 *			Florian La Roche <rzsfl@rz.uni-sb.de>
 *
 *	Fixes:
 *		Alan Cox	:	Fixed the worst of the load
 *					balancer bugs.
 *		Dave Platt	:	Interrupt stacking fix.
 *	Richard Kooijman	:	Timestamp fixes.
 *		Alan Cox	:	Changed buffer format.
 *		Alan Cox	:	destructor hook for AF_UNIX etc.
 *		Linus Torvalds	:	Better skb_clone.
 *		Alan Cox	:	Added skb_copy.
 *		Alan Cox	:	Added all the changed routines Linus
 *					only put in the headers
 *		Ray VanTassle	:	Fixed --skb->lock in free
 *		Alan Cox	:	skb_copy copy arp field
 *		Andi Kleen	:	slabified it.
 *		Robert Olsson	:	Removed skb_head_pool
 *
 *	NOTE:
 *		The __skb_ routines should be called with interrupts
 *	disabled, or you better be *real* sure that the operation is atomic
 *	with respect to whatever list is being frobbed (e.g. via lock_sock()
 *	or via disabling bottom half handlers, etc).
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

/*
 *	The functions in this file will not compile correctly with gcc 2.4.x
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/kmemcheck.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#ifdef CONFIG_NET_CLS_ACT
#include <net/pkt_sched.h>
#endif
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/splice.h>
#include <linux/cache.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/errqueue.h>

#include <net/protocol.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/xfrm.h>

#include <asm/uaccess.h>
#include <asm/system.h>
#include <trace/events/skb.h>

#include "kmap_skb.h"


//见函数skb_init, 分配SKB的两种方式见__alloc_skb
static struct kmem_cache *skbuff_head_cache; //__read_mostly; //SKB都是从该高速缓存中分配的，和下面的clone_cache的区别是，从该缓存中分配的长度为sizeof(struct sk_buff),下面的这个是2倍sizeof+sizeof(atomic_t) 
                                                           //参考32页图3-12
static struct kmem_cache *skbuff_fclone_cache; //__read_mostly;//如果在分配SKB的时候就知道可能该SKB会被克隆，那么就从这个高速缓存分配空间，这样可以提高效率 
                                                            //这里面的父子SKB指向同一块数据区data
static void sock_pipe_buf_release(struct pipe_inode_info *pipe,
				  struct pipe_buffer *buf)
{
	put_page(buf->page);
}

static void sock_pipe_buf_get(struct pipe_inode_info *pipe,
				struct pipe_buffer *buf)
{
	get_page(buf->page);
}

static int sock_pipe_buf_steal(struct pipe_inode_info *pipe,
			       struct pipe_buffer *buf)
{
	return 1;
}


/* Pipe buffer operations for a socket. */
static const struct pipe_buf_operations sock_pipe_buf_ops = {
	.can_merge = 0,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.confirm = generic_pipe_buf_confirm,
	.release = sock_pipe_buf_release,
	.steal = sock_pipe_buf_steal,
	.get = sock_pipe_buf_get,
};

/*
 *	Keep out-of-line to prevent kernel bloat.
 *	__builtin_return_address is not used because it is not always
 *	reliable.
 */

/**
 *	skb_over_panic	- 	private function
 *	@skb: buffer
 *	@sz: size
 *	@here: address
 *
 *	Out of line support code for skb_put(). Not user callable.
 */
static void skb_over_panic(struct sk_buff *skb, int sz, void *here)
{
	printk(KERN_EMERG "skb_over_panic: text:%p len:%d put:%d head:%p "
			  "data:%p tail:%#lx end:%#lx dev:%s\n",
	       here, skb->len, sz, skb->head, skb->data,
	       (unsigned long)skb->tail, (unsigned long)skb->end,
	       skb->dev ? skb->dev->name : "<NULL>");
	BUG();
}

/**
 *	skb_under_panic	- 	private function
 *	@skb: buffer
 *	@sz: size
 *	@here: address
 *
 *	Out of line support code for skb_push(). Not user callable.
 */

static void skb_under_panic(struct sk_buff *skb, int sz, void *here)
{
	printk(KERN_EMERG "skb_under_panic: text:%p len:%d put:%d head:%p "
			  "data:%p tail:%#lx end:%#lx dev:%s\n",
	       here, skb->len, sz, skb->head, skb->data,
	       (unsigned long)skb->tail, (unsigned long)skb->end,
	       skb->dev ? skb->dev->name : "<NULL>");
	BUG();
}

/* 	Allocate a new skbuff. We do this ourselves so we can fill in a few
 *	'private' fields and also do memory statistics to find all the
 *	[BEEP] leaks.
 *
 */

/**
 *	__alloc_skb	-	allocate a network buffer
 *	@size: size to allocate
 *	@gfp_mask: allocation mask
 *	@fclone: allocate from fclone cache instead of head cache
 *		and allocate a cloned (child) skb
 *	@node: numa node to allocate memory on
 *
 *	Allocate a new &sk_buff. The returned buffer has no headroom and a
 *	tail room of size bytes. The object has a reference count of one.
 *	The return is the buffer. On a failure the return is %NULL.
 *
 *	Buffers may only be allocated from interrupts using a @gfp_mask of
 *	%GFP_ATOMIC.
 size为待分配的SKB线性缓冲区的长度。
 克隆情况下分配的是两个sizeof(struct sk_buffer)。但线性数据区接非线性数据区是一个
 */
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
			    int fclone, int node)
{
	struct kmem_cache *cache;
	struct skb_shared_info *shinfo;
	struct sk_buff *skb;
	u8 *data;                                                       
	                                                                    
                                                              //skbuff_head_cache就为sizeof(sk_buffer)
	cache = fclone ? skbuff_fclone_cache : skbuff_head_cache;//定义在skbuff.c  如果是clone则从skbuff_fclone_cache分配，长度为2*sizeof(sk_buf)+4

	/* Get the HEAD  分配一个sk_buff结构的空间*/
	skb = kmem_cache_alloc_node(cache, gfp_mask & ~__GFP_DMA, node);//这里分配空间去掉DMA的原因是,DMA空间小，切有特殊用途
	if (!skb)
		goto out;
	prefetchw(skb);

	size = SKB_DATA_ALIGN(size);
	/* 分配数据缓冲区 这里包括sizeof(struct skb_shared_info) */
	data = kmalloc_node_track_caller(size + sizeof(struct skb_shared_info),//data区从DMA分配的原因是，硬件可以直接从DMA获取数据
			gfp_mask, node);
	if (!data)
		goto nodata;
	prefetchw(data + size);

	/*
	 * Only clear those fields we need to clear, not those that we will
	 * actually initialise below. Hence, don't put any more fields after
	 * the tail pointer in struct sk_buff!
	 */
	memset(skb, 0, offsetof(struct sk_buff, tail));
	skb->truesize = size + sizeof(struct sk_buff);
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);//最开始的时候head data和tail都执行线性数据头部
	skb->end = skb->tail + size;
	kmemcheck_annotate_bitfield(skb, flags1);
	kmemcheck_annotate_bitfield(skb, flags2);
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
#endif

	/* make sure we initialize shinfo sequentially */
	shinfo = skb_shinfo(skb);//shinfo执行data线性数据区的尾部
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
	atomic_set(&shinfo->dataref, 1);//前面开辟data空间的时候有算上sizeof(struct skb_shared_info)

	if (fclone) {//这时候子SKB没有指向data区   克隆情况下分配的是两个sizeof(struct sk_buffer)。但线性数据区接非线性数据区是一个
		struct sk_buff *child = skb + 1;
		atomic_t *fclone_ref = (atomic_t *) (child + 1);

		kmemcheck_annotate_bitfield(child, flags1);
		kmemcheck_annotate_bitfield(child, flags2);
		skb->fclone = SKB_FCLONE_ORIG;
		atomic_set(fclone_ref, 1);

		child->fclone = SKB_FCLONE_UNAVAILABLE;
	}
out:
	return skb;
nodata:
	kmem_cache_free(cache, skb);
	skb = NULL;
	goto out;
}
EXPORT_SYMBOL(__alloc_skb);

/**
 *	__netdev_alloc_skb - allocate an skbuff for rx on a specific device
 *	@dev: network device to receive on
 *	@length: length to allocate
 *	@gfp_mask: get_free_pages mask, passed to alloc_skb
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory.
 */
struct sk_buff *__netdev_alloc_skb(struct net_device *dev,
		unsigned int length, gfp_t gfp_mask)
{
	int node = dev->dev.parent ? dev_to_node(dev->dev.parent) : -1;
	struct sk_buff *skb;

	skb = __alloc_skb(length + NET_SKB_PAD, gfp_mask, 0, node);
	if (likely(skb)) {
		skb_reserve(skb, NET_SKB_PAD);
		skb->dev = dev;
	}
	return skb;
}
EXPORT_SYMBOL(__netdev_alloc_skb);

struct page *__netdev_alloc_page(struct net_device *dev, gfp_t gfp_mask)
{
	int node = dev->dev.parent ? dev_to_node(dev->dev.parent) : -1;
	struct page *page;

	page = alloc_pages_node(node, gfp_mask, 0);
	return page;
}
EXPORT_SYMBOL(__netdev_alloc_page);

void skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page, int off,
		int size)
{
	skb_fill_page_desc(skb, i, page, off, size);
	skb->len += size;
	skb->data_len += size;
	skb->truesize += size;
}
EXPORT_SYMBOL(skb_add_rx_frag);

/**
 *	dev_alloc_skb - allocate an skbuff for receiving
 *	@length: length to allocate
 *
 *	Allocate a new &sk_buff and assign it a usage count of one. The
 *	buffer has unspecified headroom built in. Users should allocate
 *	the headroom they think they need without accounting for the
 *	built in space. The built in space is used for optimisations.
 *
 *	%NULL is returned if there is no free memory. Although this function
 *	allocates memory it can be called from an interrupt.
 */
struct sk_buff *dev_alloc_skb(unsigned int length)
{
	/*
	 * There is more code here than it seems:
	 * __dev_alloc_skb is an inline
	 */
	return __dev_alloc_skb(length, GFP_ATOMIC);
}
EXPORT_SYMBOL(dev_alloc_skb);

static void skb_drop_list(struct sk_buff **listp)
{
	struct sk_buff *list = *listp;

	*listp = NULL;

	do {
		struct sk_buff *this = list;
		list = list->next;
		kfree_skb(this);
	} while (list);
}

//这个函数是用来释放当前skb的frag_list区的
static inline void skb_drop_fraglist(struct sk_buff *skb)
{
	skb_drop_list(&skb_shinfo(skb)->frag_list);
}

///* 对当前skb的frag_list区链上的每个skb增加引用计数。 */
static void skb_clone_fraglist(struct sk_buff *skb)
{
	struct sk_buff *list;

	skb_walk_frags(skb, list)
		skb_get(list);
}

static void skb_release_data(struct sk_buff *skb)
{
    /* 查看skb是否被clone？skb_shinfo的dataref是否为0？
        * 如果是，那么就释放skb非线性区域和线性区域。 */

	if (!skb->cloned ||
	    !atomic_sub_return(skb->nohdr ? (1 << SKB_DATAREF_SHIFT) + 1 : 1,
			       &skb_shinfo(skb)->dataref)) {
		if (skb_shinfo(skb)->nr_frags) { /* 释放page frags区 */
			int i;
			for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
				put_page(skb_shinfo(skb)->frags[i].page);
		}

		if (skb_has_frags(skb)) /* 释放frag_list区 */
			skb_drop_fraglist(skb);

		kfree(skb->head);/* 释放线性区域 */
	}
}

/*
 *	Free an skbuff by memory without cleaning the state.
 /* 把skb自身和线性，非线性区域全部释放
 */
static void kfree_skbmem(struct sk_buff *skb)
{
	struct sk_buff *other;
	atomic_t *fclone_ref;

	switch (skb->fclone) {
	case SKB_FCLONE_UNAVAILABLE:
		kmem_cache_free(skbuff_head_cache, skb);
		break;

	case SKB_FCLONE_ORIG://释放父SKB
		fclone_ref = (atomic_t *) (skb + 2);
		if (atomic_dec_and_test(fclone_ref))
			kmem_cache_free(skbuff_fclone_cache, skb);
		break;

	case SKB_FCLONE_CLONE://释放子SKB
		fclone_ref = (atomic_t *) (skb + 1);
		other = skb - 1;

		/* The clone portion is available for
		 * fast-cloning again.
		 */
		skb->fclone = SKB_FCLONE_UNAVAILABLE;

		if (atomic_dec_and_test(fclone_ref))
			kmem_cache_free(skbuff_fclone_cache, other);
		break;
	}
}

//释放分片相关skb_shared_info相关的内存
static void skb_release_head_state(struct sk_buff *skb)
{
	skb_dst_drop(skb);
#ifdef CONFIG_XFRM
	secpath_put(skb->sp);
#endif
	if (skb->destructor) {
		WARN_ON(in_irq());
		skb->destructor(skb);
	}
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	nf_conntrack_put(skb->nfct);
	nf_conntrack_put_reasm(skb->nfct_reasm);
#endif
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(skb->nf_bridge);
#endif
/* XXX: IS this still necessary? - JHS */
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = 0;
#endif
#endif
}

/* Free everything but the sk_buff shell. */
static void skb_release_all(struct sk_buff *skb)
{
	skb_release_head_state(skb);
	skb_release_data(skb);
}

/**
 *	__kfree_skb - private function
 *	@skb: buffer
 *
 *	Free an sk_buff. Release anything attached to the buffer.
 *	Clean the state. This is an internal helper function. Users should
 *	always call kfree_skb
 */

void __kfree_skb(struct sk_buff *skb)
{
	skb_release_all(skb);//释放data数据部分，包括扩shareinof分片的
	kfree_skbmem(skb);//释放SKB描述符
}
EXPORT_SYMBOL(__kfree_skb);

/**
 *	kfree_skb - free an sk_buff
 *	@skb: buffer to free
 *
 *	Drop a reference to the buffer and free it if the usage count has
 *	hit zero.
 user引用计数为0的时候才真正释放空间
 */
void kfree_skb(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return;
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users)))
		return;
	trace_kfree_skb(skb, __builtin_return_address(0));
	__kfree_skb(skb);
}
EXPORT_SYMBOL(kfree_skb);

/**
 *	consume_skb - free an skbuff
 *	@skb: buffer to free
 *
 *	Drop a ref to the buffer and free it if the usage count has hit zero
 *	Functions identically to kfree_skb, but kfree_skb assumes that the frame
 *	is being dropped after a failure and notes that
 */
void consume_skb(struct sk_buff *skb)
{
	if (unlikely(!skb))
		return;
	if (likely(atomic_read(&skb->users) == 1))
		smp_rmb();
	else if (likely(!atomic_dec_and_test(&skb->users)))
		return;
	__kfree_skb(skb);
}
EXPORT_SYMBOL(consume_skb);

/**
 *	skb_recycle_check - check if skb can be reused for receive
 *	@skb: buffer
 *	@skb_size: minimum receive buffer size
 *
 *	Checks that the skb passed in is not shared or cloned, and
 *	that it is linear and its head portion at least as large as
 *	skb_size so that it can be recycled as a receive buffer.
 *	If these conditions are met, this function does any necessary
 *	reference count dropping and cleans up the skbuff as if it
 *	just came from __alloc_skb().
 */
bool skb_recycle_check(struct sk_buff *skb, int skb_size)
{
	struct skb_shared_info *shinfo;

	if (irqs_disabled())
		return false;

	if (skb_is_nonlinear(skb) || skb->fclone != SKB_FCLONE_UNAVAILABLE)
		return false;

	skb_size = SKB_DATA_ALIGN(skb_size + NET_SKB_PAD);
	if (skb_end_pointer(skb) - skb->head < skb_size)
		return false;

	if (skb_shared(skb) || skb_cloned(skb))
		return false;

	skb_release_head_state(skb);

	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
	atomic_set(&shinfo->dataref, 1);

	memset(skb, 0, offsetof(struct sk_buff, tail));
	skb->data = skb->head + NET_SKB_PAD;
	skb_reset_tail_pointer(skb);

	return true;
}
EXPORT_SYMBOL(skb_recycle_check);

static void __copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
	new->tstamp		= old->tstamp;
	new->dev		= old->dev;
	new->transport_header	= old->transport_header;
	new->network_header	= old->network_header;
	new->mac_header		= old->mac_header;
	skb_dst_copy(new, old);
	new->rxhash		= old->rxhash;
#ifdef CONFIG_XFRM
	new->sp			= secpath_get(old->sp);
#endif
	memcpy(new->cb, old->cb, sizeof(old->cb));
	new->csum		= old->csum;
	new->local_df		= old->local_df;
	new->pkt_type		= old->pkt_type;
	new->ip_summed		= old->ip_summed;
	skb_copy_queue_mapping(new, old);
	new->priority		= old->priority;
	new->deliver_no_wcard	= old->deliver_no_wcard;
#if defined(CONFIG_IP_VS) || defined(CONFIG_IP_VS_MODULE)
	new->ipvs_property	= old->ipvs_property;
#endif
	new->protocol		= old->protocol;
	new->mark		= old->mark;
	new->skb_iif		= old->skb_iif;
	__nf_copy(new, old);
#if defined(CONFIG_NETFILTER_XT_TARGET_TRACE) || \
    defined(CONFIG_NETFILTER_XT_TARGET_TRACE_MODULE)
	new->nf_trace		= old->nf_trace;
#endif
#ifdef CONFIG_NET_SCHED
	new->tc_index		= old->tc_index;
#ifdef CONFIG_NET_CLS_ACT
	new->tc_verd		= old->tc_verd;
#endif
#endif
	new->vlan_tci		= old->vlan_tci;

	skb_copy_secmark(new, old);
}

/*
 * You should not add any new code to this function.  Add it to
 * __copy_skb_header above instead.
 */
 //SKB标示父SKB,n标示子SKB  两个SKB头部struct完全相同，并指向相同的数据区
static struct sk_buff *__skb_clone(struct sk_buff *n, struct sk_buff *skb)
{
#define C(x) n->x = skb->x

	n->next = n->prev = NULL;
	n->sk = NULL;
	__copy_skb_header(n, skb);

	C(len);
	C(data_len);
	C(mac_len);
	n->hdr_len = skb->nohdr ? skb_headroom(skb) : skb->hdr_len;
	n->cloned = 1;
	n->nohdr = 0;
	n->destructor = NULL;
	C(tail);
	C(end);
	C(head);
	C(data);
	C(truesize);
	atomic_set(&n->users, 1);

	atomic_inc(&(skb_shinfo(skb)->dataref));//又多了一个SKB指向数据部分
	skb->cloned = 1;

	return n;
#undef C
}

/**
 *	skb_morph	-	morph one skb into another
 *	@dst: the skb to receive the contents
 *	@src: the skb to supply the contents
 *
 *	This is identical to skb_clone except that the target skb is
 *	supplied by the user.
 *
 *	The target skb is returned upon exit.
 */
struct sk_buff *skb_morph(struct sk_buff *dst, struct sk_buff *src)
{
	skb_release_all(dst);
	return __skb_clone(dst, src);
}
EXPORT_SYMBOL_GPL(skb_morph);

/**
 *	skb_clone	-	duplicate an sk_buff
 *	@skb: buffer to clone
 *	@gfp_mask: allocation priority
 *
 *	Duplicate an &sk_buff. The new one is not owned by a socket. Both
 *	copies share the same packet data but not structure. The new
 *	buffer has a reference count of 1. If the allocation fails the
 *	function returns %NULL otherwise the new buffer is returned.
 *
 *	If this function is called from an interrupt gfp_mask() must be
 *	%GFP_ATOMIC.
 */
//克隆只是分配SKB，并增加数据缓冲区的引用计数     skb_clone一般只修改数据SKB描述符，pskb_copy的使用场合一般是既要修改SKB描述符，也要修改数据缓冲区部分，所有SKB和data区要同时复制
//新的skb的data指针和skb data指针指向同一个data，skb结构是新的skb。 一般在以下情况下使用:当指需要修改skb结构部分，而不需要修改data数据(包括二 三层等，也包括data数据payload部分)的时候用这个
//注意参数SKB必须是__alloc_skb中为fclone情况下分片的SKB
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask) //注意skb_clone和pskb_copy()与skb_copy()的区别
{
	struct sk_buff *n;

	n = skb + 1;//子SKB
	/* 判断原始skb是否是从skbuff_fclone_cache 缓冲区中分配的，从skbuff_fclone_cache 分配将预先为clone的skb分配好内存，同时判定该预先分配的clone skb是否被使用 */
	if (skb->fclone == SKB_FCLONE_ORIG &&
	    n->fclone == SKB_FCLONE_UNAVAILABLE) { //表面是从skbuff_fclone_cache中分配的SKB,子SKB的data区是空的
		atomic_t *fclone_ref = (atomic_t *) (n + 1);//N+1刚好对应skbuff_fclone_cache中分配空间的最后四字节，用来表示应用技术
		n->fclone = SKB_FCLONE_CLONE;/* 置clone的skb中fclone值为SKB_FCLONE_CLONE ，标明其数据区指向原始skb同一数据区 */
		atomic_inc(fclone_ref);
	} else {//从新分配一个skb  /* 主skb并未同时分配clone skb的情况，将重新独立分配skb结构作为clone的skb */
		n = kmem_cache_alloc(skbuff_head_cache, gfp_mask);
		if (!n)
			return NULL;

		kmemcheck_annotate_bitfield(n, flags1);
		kmemcheck_annotate_bitfield(n, flags2);
		n->fclone = SKB_FCLONE_UNAVAILABLE;
	}

	return __skb_clone(n, skb);
}
EXPORT_SYMBOL(skb_clone);

static void copy_skb_header(struct sk_buff *new, const struct sk_buff *old)
{
#ifndef NET_SKBUFF_DATA_USES_OFFSET
	/*
	 *	Shift between the two data areas in bytes
	 */
	unsigned long offset = new->data - old->data;
#endif

	__copy_skb_header(new, old);

#ifndef NET_SKBUFF_DATA_USES_OFFSET
	/* {transport,network,mac}_header are relative to skb->head */
	new->transport_header += offset;
	new->network_header   += offset;
	if (skb_mac_header_was_set(new))
		new->mac_header	      += offset;
#endif
	skb_shinfo(new)->gso_size = skb_shinfo(old)->gso_size;
	skb_shinfo(new)->gso_segs = skb_shinfo(old)->gso_segs;
	skb_shinfo(new)->gso_type = skb_shinfo(old)->gso_type;
}

/**
 *	skb_copy	-	create private copy of an sk_buff
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data. This is used when the
 *	caller wishes to modify the data and needs a private copy of the
 *	data to alter. Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	As by-product this function converts non-linear &sk_buff to linear
 *	one, so that &sk_buff becomes completely private and caller is allowed
 *	to modify all the data of returned buffer. This means that this
 *	function is not recommended for use in circumstances when only
 *	header is going to be modified. Use pskb_copy() instead.
 */
//如果要复制SKB  data区和分片相关，只能用skb_copy，pskb_copy不能复制分片相关的,pskb_copy值复制head和data之间的数据  //复制SKB描述符，data区以及分片区  参考41页
//pskb_copy和skb_copy的区别是pskb不需要拷贝skb_shinfo中的数据，skb_copy则需要修改skb_shinfo中的数据
struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp_mask)//注意skb_clone和pskb_copy()与skb_copy()的区别
{
	int headerlen = skb->data - skb->head;
	/*
	 *	Allocate the copy buffer
	 */
	struct sk_buff *n;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	n = alloc_skb(skb->end + skb->data_len, gfp_mask);
#else
	n = alloc_skb(skb->end - skb->head + skb->data_len, gfp_mask);
#endif
	if (!n)
		return NULL;

	/* Set the data pointer */
	skb_reserve(n, headerlen);
	/* Set the tail pointer and length */
	skb_put(n, skb->len);

	if (skb_copy_bits(skb, -headerlen, n->head, headerlen + skb->len))
		BUG();

	copy_skb_header(n, skb);
	return n;
}
EXPORT_SYMBOL(skb_copy);

/**
 *	pskb_copy	-	create copy of an sk_buff with private head.
 *	@skb: buffer to copy
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and part of its data, located
 *	in header. Fragmented data remain shared. This is used when
 *	the caller wishes to modify only header of &sk_buff and needs
 *	private copy of the header to alter. Returns %NULL on failure
 *	or the pointer to the buffer on success.
 *	The returned buffer has a reference count of 1.
 */
//只复制一份SKB描述符，并复制基本的data区，不包括分片的数据        参考41页
//pskb_copy和skb_copy的区别是pskb不需要拷贝skb_shinfo(这部分数据时共享的)中的数据，skb_copy则需要修改skb_shinfo(各自有独立的shinfo数据)中的数据
struct sk_buff *pskb_copy(struct sk_buff *skb, gfp_t gfp_mask)//注意skb_clone和pskb_copy()与skb_copy()的区别
{
	/*
	 *	Allocate the copy buffer
	 */
	struct sk_buff *n;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	n = alloc_skb(skb->end, gfp_mask);
#else
	n = alloc_skb(skb->end - skb->head, gfp_mask);
#endif
	if (!n)
		goto out;

	/* Set the data pointer */
	skb_reserve(n, skb->data - skb->head);
	/* Set the tail pointer and length */
	skb_put(n, skb_headlen(skb));
	/* Copy the bytes */
	skb_copy_from_linear_data(skb, n->data, n->len);

	n->truesize += skb->data_len;
	n->data_len  = skb->data_len;
	n->len	     = skb->len;

	if (skb_shinfo(skb)->nr_frags) {
		int i;

		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			skb_shinfo(n)->frags[i] = skb_shinfo(skb)->frags[i];
			get_page(skb_shinfo(n)->frags[i].page);
		}
		skb_shinfo(n)->nr_frags = i;
	}

	if (skb_has_frags(skb)) {
		skb_shinfo(n)->frag_list = skb_shinfo(skb)->frag_list;
		skb_clone_fraglist(n);
	}

	copy_skb_header(n, skb);
out:
	return n;
}
EXPORT_SYMBOL(pskb_copy);

/**
 *	pskb_expand_head - reallocate header of &sk_buff
 *	@skb: buffer to reallocate
 *	@nhead: room to add at head
 *	@ntail: room to add at tail
 *	@gfp_mask: allocation priority
 *
 *	Expands (or creates identical copy, if &nhead and &ntail are zero)
 *	header of skb. &sk_buff itself is not changed. &sk_buff MUST have
 *	reference count of 1. Returns zero in the case of success or error,
 *	if expansion failed. In the last case, &sk_buff is not changed.
 *
 *	All the pointers pointing into skb header may change and must be
 *	reloaded after call to this function.
 */
 //nhead为扩展的headroom空间的长度，nhead是向前扩展，ntail向后扩展，ntail为扩展的tailroom空间的长度。参考46页码图3-30 全部都变为线性缓冲区
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,//注意skb_cow  skb_realloc_headroom和pskb_expand_head的区别
		     gfp_t gfp_mask)
{
	int i;
	u8 *data;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	int size = nhead + skb->end + ntail;
#else
	int size = nhead + (skb->end - skb->head) + ntail;
#endif
	long off;

	BUG_ON(nhead < 0);

	if (skb_shared(skb))//该SKB只能被应用一次
		BUG();

	size = SKB_DATA_ALIGN(size);

	data = kmalloc(size + sizeof(struct skb_shared_info), gfp_mask);
	if (!data)
		goto nodata;

	/* Copy only real data... and, alas, header. This should be
	 * optimized for the cases when header is void. */
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	memcpy(data + nhead, skb->head, skb->tail);
#else
	memcpy(data + nhead, skb->head, skb->tail - skb->head);//拷贝data区
#endif
	memcpy(data + size, skb_end_pointer(skb),
	       sizeof(struct skb_shared_info));//拷贝非线性区，即分片区

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		get_page(skb_shinfo(skb)->frags[i].page);

	if (skb_has_frags(skb))//表示frag_list不为NULL，即有分片缓存在该frag_list链表上面
		skb_clone_fraglist(skb);

	skb_release_data(skb);

	off = (data + nhead) - skb->head;

	skb->head     = data;
	skb->data    += off;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->end      = size;
	off           = nhead;
#else
	skb->end      = skb->head + size;
#endif
	/* {transport,network,mac}_header and tail are relative to skb->head */
	skb->tail	      += off;
	skb->transport_header += off;
	skb->network_header   += off;
	if (skb_mac_header_was_set(skb))
		skb->mac_header += off;
	/* Only adjust this if it actually is csum_start rather than csum */
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		skb->csum_start += nhead;
	skb->cloned   = 0;
	skb->hdr_len  = 0;
	skb->nohdr    = 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return 0;

nodata:
	return -ENOMEM;
}
EXPORT_SYMBOL(pskb_expand_head);

/* Make private copy of skb with writable head and some headroom */
//创建一个新的skb描述符，同时给这个新的skb描述符扩展headroom个头部字节，源skb在该函数中并没有释放
struct sk_buff *skb_realloc_headroom(struct sk_buff *skb, unsigned int headroom) 
//注意skb_cow skb_ realloc_headroom和pskb_expand_head的区别
//headroom指的是data区域前面的剩余空间，tailroom指的是tail后面剩下的线性空间，见樊东东上P43
{
	struct sk_buff *skb2;
	int delta = headroom - skb_headroom(skb);

	if (delta <= 0)
		skb2 = pskb_copy(skb, GFP_ATOMIC);
	else {
		skb2 = skb_clone(skb, GFP_ATOMIC);
		if (skb2 && pskb_expand_head(skb2, SKB_DATA_ALIGN(delta), 0,
					     GFP_ATOMIC)) {
			kfree_skb(skb2);
			skb2 = NULL;
		}
	}
	return skb2;
}
EXPORT_SYMBOL(skb_realloc_headroom);

/**
 *	skb_copy_expand	-	copy and expand sk_buff
 *	@skb: buffer to copy
 *	@newheadroom: new free bytes at head
 *	@newtailroom: new free bytes at tail
 *	@gfp_mask: allocation priority
 *
 *	Make a copy of both an &sk_buff and its data and while doing so
 *	allocate additional space.
 *
 *	This is used when the caller wishes to modify the data and needs a
 *	private copy of the data to alter as well as more space for new fields.
 *	Returns %NULL on failure or the pointer to the buffer
 *	on success. The returned buffer has a reference count of 1.
 *
 *	You must pass %GFP_ATOMIC as the allocation priority if this function
 *	is called from an interrupt.
 */
struct sk_buff *skb_copy_expand(const struct sk_buff *skb,
				int newheadroom, int newtailroom,
				gfp_t gfp_mask)
{
	/*
	 *	Allocate the copy buffer
	 */
	struct sk_buff *n = alloc_skb(newheadroom + skb->len + newtailroom,
				      gfp_mask);
	int oldheadroom = skb_headroom(skb);
	int head_copy_len, head_copy_off;
	int off;

	if (!n)
		return NULL;

	skb_reserve(n, newheadroom);

	/* Set the tail pointer and length */
	skb_put(n, skb->len);

	head_copy_len = oldheadroom;
	head_copy_off = 0;
	if (newheadroom <= head_copy_len)
		head_copy_len = newheadroom;
	else
		head_copy_off = newheadroom - head_copy_len;

	/* Copy the linear header and data. */
	if (skb_copy_bits(skb, -head_copy_len, n->head + head_copy_off,
			  skb->len + head_copy_len))
		BUG();

	copy_skb_header(n, skb);

	off                  = newheadroom - oldheadroom;
	if (n->ip_summed == CHECKSUM_PARTIAL)
		n->csum_start += off;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	n->transport_header += off;
	n->network_header   += off;
	if (skb_mac_header_was_set(skb))
		n->mac_header += off;
#endif

	return n;
}
EXPORT_SYMBOL(skb_copy_expand);

/**
 *	skb_pad			-	zero pad the tail of an skb
 *	@skb: buffer to pad
 *	@pad: space to pad
 *
 *	Ensure that a buffer is followed by a padding area that is zero
 *	filled. Used by network drivers which may DMA or transfer data
 *	beyond the buffer end onto the wire.
 *
 *	May return error in out of memory cases. The skb is freed on error.
 */

int skb_pad(struct sk_buff *skb, int pad)
{
	int err;
	int ntail;

	/* If the skbuff is non linear tailroom is always zero.. */
	if (!skb_cloned(skb) && skb_tailroom(skb) >= pad) {
		memset(skb->data+skb->len, 0, pad);
		return 0;
	}

	ntail = skb->data_len + pad - (skb->end - skb->tail);
	if (likely(skb_cloned(skb) || ntail > 0)) {
		err = pskb_expand_head(skb, 0, ntail, GFP_ATOMIC);
		if (unlikely(err))
			goto free_skb;
	}

	/* FIXME: The use of this function with non-linear skb's really needs
	 * to be audited.
	 */
	err = skb_linearize(skb);
	if (unlikely(err))
		goto free_skb;

	memset(skb->data + skb->len, 0, pad);
	return 0;

free_skb:
	kfree_skb(skb);
	return err;
}
EXPORT_SYMBOL(skb_pad);

/**
 *	skb_put - add data to a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer. If this would
 *	exceed the total buffer size the kernel will panic. A pointer to the
 *	first byte of the extra data is returned.
 */
 /*
 skb_put向后填充，data不变，tail向右移动，len增加; 
 skb_push 向前填充，data前移，tail不变，len增加
 skb_pull 取数据，data后移,tail不变,len减少
 skb_reserve data和tail同时向后移动相同len，实际上len还是不变，只是headerroom增加了
 参考http://www.cnblogs.com/qq78292959/archive/2012/06/06/2538358.html
*/
unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = skb_tail_pointer(skb);
	SKB_LINEAR_ASSERT(skb);
	skb->tail += len;
	skb->len  += len;
	if (unlikely(skb->tail > skb->end))
		skb_over_panic(skb, len, __builtin_return_address(0));
	return tmp;
}
EXPORT_SYMBOL(skb_put);

/**
 *	skb_push - add data to the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to add
 *
 *	This function extends the used data area of the buffer at the buffer
 *	start. If this would exceed the total buffer headroom the kernel will
 *	panic. A pointer to the first byte of the extra data is returned.
 */ /*
 skb_put向后填充，data不变，tail向右移动，len增加; 
 skb_push 向前填充，data前移，tail不变，len增加
 skb_pull 取数据，data后移,tail不变,len减少
 skb_reserve data和tail同时向后移动相同len，实际上len还是不变，只是headerroom增加了
 参考http://www.cnblogs.com/qq78292959/archive/2012/06/06/2538358.html
*/
unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	if (unlikely(skb->data<skb->head))
		skb_under_panic(skb, len, __builtin_return_address(0));
	return skb->data;
}
EXPORT_SYMBOL(skb_push);

/**
 *	skb_pull - remove data from the start of a buffer
 *	@skb: buffer to use
 *	@len: amount of data to remove
 *
 *	This function removes data from the start of a buffer, returning
 *	the memory to the headroom. A pointer to the next data in the buffer
 *	is returned. Once the data has been pulled future pushes will overwrite
 *	the old data.
 */ /*
 skb_put向后填充，data不变，tail向右移动，len增加; 
 skb_push 向前填充，data前移，tail不变，len增加
 skb_pull 取数据，data后移,tail不变,len减少
 skb_reserve data和tail同时向后移动相同len，实际上len还是不变，只是headerroom增加了
 参考http://www.cnblogs.com/qq78292959/archive/2012/06/06/2538358.html
*/
unsigned char *skb_pull(struct sk_buff *skb, unsigned int len)
{
	return skb_pull_inline(skb, len);
}
EXPORT_SYMBOL(skb_pull);

/**
 *	skb_trim - remove end from a buffer
 *	@skb: buffer to alter
 *	@len: new length
 *
 *	Cut the length of a buffer down by removing data from the tail. If
 *	the buffer is already under the length specified it is not modified.
 *	The skb must be linear.
 *///skb_trim与skb_add_data想对应，一个是删除一部分尾部数据，一个是向尾部追加数据。他们都只是对线性数据进行处理。pskb_trim还可以对非线性分散聚合I/O数据进行裁剪
 //该函数指对线性数据空间进行尾部清除操作。如果需要对skb_shinfo做清除处理，则用pskb_trim函数，见樊东东P44
void skb_trim(struct sk_buff *skb, unsigned int len) //skb_trim与skb_add_data想对应，一个是删除一部分尾部数据，一个是向尾部追加数据
{
	if (skb->len > len)
		__skb_trim(skb, len);
}
EXPORT_SYMBOL(skb_trim);

/* Trims skb to length len. It can change skb pointers.
 */
//可以删除data区的数据，还可以删除分片区的数据
int ___pskb_trim(struct sk_buff *skb, unsigned int len)
{
	struct sk_buff **fragp;
	struct sk_buff *frag;
	int offset = skb_headlen(skb);
	int nfrags = skb_shinfo(skb)->nr_frags;
	int i;
	int err;

	if (skb_cloned(skb) &&
	    unlikely((err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC))))
		return err;

	i = 0;
	if (offset >= len)
		goto drop_pages;

	for (; i < nfrags; i++) {
		int end = offset + skb_shinfo(skb)->frags[i].size;

		if (end < len) {
			offset = end;
			continue;
		}

		skb_shinfo(skb)->frags[i++].size = len - offset;

drop_pages:
		skb_shinfo(skb)->nr_frags = i;

		for (; i < nfrags; i++)
			put_page(skb_shinfo(skb)->frags[i].page);

		if (skb_has_frags(skb))
			skb_drop_fraglist(skb);
		goto done;
	}

	for (fragp = &skb_shinfo(skb)->frag_list; (frag = *fragp);
	     fragp = &frag->next) {
		int end = offset + frag->len;

		if (skb_shared(frag)) {
			struct sk_buff *nfrag;

			nfrag = skb_clone(frag, GFP_ATOMIC);
			if (unlikely(!nfrag))
				return -ENOMEM;

			nfrag->next = frag->next;
			kfree_skb(frag);
			frag = nfrag;
			*fragp = frag;
		}

		if (end < len) {
			offset = end;
			continue;
		}

		if (end > len &&
		    unlikely((err = pskb_trim(frag, len - offset))))
			return err;

		if (frag->next)
			skb_drop_list(&frag->next);
		break;
	}

done:
	if (len > skb_headlen(skb)) {
		skb->data_len -= skb->len - len;
		skb->len       = len;
	} else {
		skb->len       = len;
		skb->data_len  = 0;
		skb_set_tail_pointer(skb, len);
	}

	return 0;
}
EXPORT_SYMBOL(___pskb_trim);

/**
 *	__pskb_pull_tail - advance tail of skb header
 *	@skb: buffer to reallocate
 *	@delta: number of bytes to advance tail
 *
 *	The function makes a sense only on a fragmented &sk_buff,
 *	it expands header moving its tail forward and copying necessary
 *	data from fragmented part.
 *
 *	&sk_buff MUST have reference count of 1.
 *
 *	Returns %NULL (and &sk_buff does not change) if pull failed
 *	or value of new tail of skb in the case of success.
 *
 *	All the pointers pointing into skb header may change and must be
 *	reloaded after call to this function.
 */

/* Moves tail of skb head forward, copying data from fragmented part,
 * when it is necessary.
 * 1. It may fail due to malloc failure.
 * 2. It may change skb pointers.
 *
 * It is pretty complicated. Luckily, it is called only in exceptional cases.
 */ //把SKB中的分散聚合I/O中的数据线性化，保证分散聚合I/O中的数据和线性区的数据放在一起
 //实际上是分配一个大的线性区域，把之前的线性区和分散聚合I/O数据拷贝过去
unsigned char *__pskb_pull_tail(struct sk_buff *skb, int delta)
{
	/* If skb has not enough free space at tail, get new one
	 * plus 128 bytes for future expansions. If we have enough
	 * room at tail, reallocate without expansion only if skb is cloned.
	 */
	int i, k, eat = (skb->tail + delta) - skb->end;

	if (eat > 0 || skb_cloned(skb)) {
		if (pskb_expand_head(skb, 0, eat > 0 ? eat + 128 : 0,
				     GFP_ATOMIC)) //扩展线性缓冲区长度，保证下面的skb_copy_bits拷贝数据，内存空间够
			return NULL;
	}

	if (skb_copy_bits(skb, skb_headlen(skb), skb_tail_pointer(skb), delta)) //注意这里线性区和分散聚合I/O区的数据都拷贝了
		BUG();

    //由于数据已经拷贝到了skb->data中，因此需要释放frags,frag_list中被拷贝过的数据  
    //计算从frags数组中拷贝的数据量  
    
	/* Optimization: no fragments, no reasons to preestimate
	 * size of pulled pages. Superb.
	 */
	if (!skb_has_frags(skb))
		goto pull_pages;

	/* Estimate size of pulled pages. */
	eat = delta;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size >= eat)//寻找到满足eat这么多数据量的最后一个page  
			goto pull_pages;//在frags数组中的数据量可以满足delta时，则只释放frags即可  
		eat -= skb_shinfo(skb)->frags[i].size;
	}

	/* If we need update frag list, we are in troubles.
	 * Certainly, it possible to add an offset to skb data,
	 * but taking into account that pulling is expected to
	 * be very rare operation, it is worth to fight against
	 * further bloating skb head and crucify ourselves here instead.
	 * Pure masohism, indeed. 8)8)
	 */ //eat仍不为0，说明从frag_list中进行了拷贝，释放frag_list  
	if (eat) {
		struct sk_buff *list = skb_shinfo(skb)->frag_list;
		struct sk_buff *clone = NULL;
		struct sk_buff *insp = NULL;

		do {
			BUG_ON(!list);

			if (list->len <= eat) {//当前skb的长度小于需要的长度  
				/* Eaten as whole. */
				eat -= list->len;//找到下一个skb  
				list = list->next;//list指向下一个需要的skb  
				insp = list;//insp指向当前的skb  
			} else {
				/* Eaten partially. */
                //此时insp指向前一个skb  
                //说明当前skb可以满足需要的数据量   
				if (skb_shared(list)) {//但是当前skb被共享  
					/* Sucks! We need to fork list. :-( */
					clone = skb_clone(list, GFP_ATOMIC);//对最后那个拷贝不完全的skb，进行克隆 
					if (!clone)
						return NULL;
					//list指向当前被克隆的的skb  
                    //insp指向下一个skb   
					insp = list->next;
					list = clone;
				} else {
					/* This may be pulled without
					 * problems. */
					insp = list;//list与insp指向当前的skb  
				}
				if (!pskb_pull(list, eat)) {//修改最后一个skb，移动指针，删除掉被拷贝的数据  
					kfree_skb(clone);
					return NULL;
				}
				break;
			}
		} while (eat);
        //list指向frag_list头  
        //直到list遍历到数据量足够的最后一个skb   
		/* Free pulled out fragments. */
		while ((list = skb_shinfo(skb)->frag_list) != insp) {
			skb_shinfo(skb)->frag_list = list->next;
			kfree_skb(list);//递减当前skb的引用技术，如果引用计数=0，则释放list  
		}
		/* And insert new clone at head. */
		if (clone) {//说明最后一个skb只被拷贝了一部分，将此skb挂到frag_list头  
			clone->next = list;
			skb_shinfo(skb)->frag_list = clone;
		}
	}
	/* Success! Now we may commit changes to skb data. */

pull_pages://释放frags中的page  
	eat = delta;
	k = 0;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k;

	skb->tail     += delta;
	skb->data_len -= delta;

	return skb_tail_pointer(skb);
}
EXPORT_SYMBOL(__pskb_pull_tail);

/* Copy some data bits from skb to kernel buffer. */
//memcpy(to, skb->data + offset, len);从SKB的data处拷贝len字节数据到to缓冲区
//将skb中起始offset的内容拷贝到to中，拷贝长度为len 。拷贝线性区和分散聚合I/O区的数据一起放到线性缓冲区。
int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len)
{
	int start = skb_headlen(skb);
	struct sk_buff *frag_iter;
	int i, copy;

	if (offset > (int)skb->len - len)
		goto fault;

	/* Copy header. */
	if ((copy = start - offset) > 0) {// 拷贝在当前页面中的部分
		if (copy > len)
			copy = len;
		skb_copy_from_linear_data_offset(skb, offset, to, copy);
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		to     += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {// 拷贝本skb中其他碎片中的部分
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;

			vaddr = kmap_skb_frag(&skb_shinfo(skb)->frags[i]);//映射skb的frag到内核地址空间  
			memcpy(to,
			       vaddr + skb_shinfo(skb)->frags[i].page_offset+
			       offset - start, copy);//拷贝  
			kunmap_skb_frag(vaddr);//解除映射  

			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to     += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {// 拷贝其他碎片skb中的数据部分
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			if (skb_copy_bits(frag_iter, offset - start, to, copy))
				goto fault;
			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			to     += copy;
		}
		start = end;
	}
	if (!len)
		return 0;

fault:
	return -EFAULT;
}
EXPORT_SYMBOL(skb_copy_bits);

/*
 * Callback from splice_to_pipe(), if we need to release some pages
 * at the end of the spd in case we error'ed out in filling the pipe.
 */
static void sock_spd_release(struct splice_pipe_desc *spd, unsigned int i)
{
	put_page(spd->pages[i]);
}

static inline struct page *linear_to_page(struct page *page, unsigned int *len,
					  unsigned int *offset,
					  struct sk_buff *skb, struct sock *sk)
{
	struct page *p = sk->sk_sndmsg_page;
	unsigned int off;

	if (!p) {
new_page:
		p = sk->sk_sndmsg_page = alloc_pages(sk->sk_allocation, 0);
		if (!p)
			return NULL;

		off = sk->sk_sndmsg_off = 0;
		/* hold one ref to this page until it's full */
	} else {
		unsigned int mlen;

		off = sk->sk_sndmsg_off;
		mlen = PAGE_SIZE - off;
		if (mlen < 64 && mlen < *len) {
			put_page(p);
			goto new_page;
		}

		*len = min_t(unsigned int, *len, mlen);
	}

	memcpy(page_address(p) + off, page_address(page) + *offset, *len);
	sk->sk_sndmsg_off += *len;
	*offset = off;
	get_page(p);

	return p;
}

/*
 * Fill page/offset/length into spd, if it can hold more pages.
 */
static inline int spd_fill_page(struct splice_pipe_desc *spd,
				struct pipe_inode_info *pipe, struct page *page,
				unsigned int *len, unsigned int offset,
				struct sk_buff *skb, int linear,
				struct sock *sk)
{
	if (unlikely(spd->nr_pages == pipe->buffers))
		return 1;

	if (linear) {
		page = linear_to_page(page, len, &offset, skb, sk);
		if (!page)
			return 1;
	} else
		get_page(page);

	spd->pages[spd->nr_pages] = page;
	spd->partial[spd->nr_pages].len = *len;
	spd->partial[spd->nr_pages].offset = offset;
	spd->nr_pages++;

	return 0;
}

static inline void __segment_seek(struct page **page, unsigned int *poff,
				  unsigned int *plen, unsigned int off)
{
	unsigned long n;

	*poff += off;
	n = *poff / PAGE_SIZE;
	if (n)
		*page = nth_page(*page, n);

	*poff = *poff % PAGE_SIZE;
	*plen -= off;
}

static inline int __splice_segment(struct page *page, unsigned int poff,
				   unsigned int plen, unsigned int *off,
				   unsigned int *len, struct sk_buff *skb,
				   struct splice_pipe_desc *spd, int linear,
				   struct sock *sk,
				   struct pipe_inode_info *pipe)
{
	if (!*len)
		return 1;

	/* skip this segment if already processed */
	if (*off >= plen) {
		*off -= plen;
		return 0;
	}

	/* ignore any bits we already processed */
	if (*off) {
		__segment_seek(&page, &poff, &plen, *off);
		*off = 0;
	}

	do {
		unsigned int flen = min(*len, plen);

		/* the linear region may spread across several pages  */
		flen = min_t(unsigned int, flen, PAGE_SIZE - poff);

		if (spd_fill_page(spd, pipe, page, &flen, poff, skb, linear, sk))
			return 1;

		__segment_seek(&page, &poff, &plen, flen);
		*len -= flen;

	} while (*len && plen);

	return 0;
}

/*
 * Map linear and fragment data from the skb to spd. It reports failure if the
 * pipe is full or if we already spliced the requested length.
 */
static int __skb_splice_bits(struct sk_buff *skb, struct pipe_inode_info *pipe,
			     unsigned int *offset, unsigned int *len,
			     struct splice_pipe_desc *spd, struct sock *sk)
{
	int seg;

	/*
	 * map the linear part
	 */
	if (__splice_segment(virt_to_page(skb->data),
			     (unsigned long) skb->data & (PAGE_SIZE - 1),
			     skb_headlen(skb),
			     offset, len, skb, spd, 1, sk, pipe))
		return 1;

	/*
	 * then map the fragments
	 */
	for (seg = 0; seg < skb_shinfo(skb)->nr_frags; seg++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[seg];

		if (__splice_segment(f->page, f->page_offset, f->size,
				     offset, len, skb, spd, 0, sk, pipe))
			return 1;
	}

	return 0;
}

/*
 * Map data from the skb to a pipe. Should handle both the linear part,
 * the fragments, and the frag list. It does NOT handle frag lists within
 * the frag list, if such a thing exists. We'd probably need to recurse to
 * handle that cleanly.
 */
int skb_splice_bits(struct sk_buff *skb, unsigned int offset,
		    struct pipe_inode_info *pipe, unsigned int tlen,
		    unsigned int flags)
{
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct page *pages[PIPE_DEF_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.flags = flags,
		.ops = &sock_pipe_buf_ops,
		.spd_release = sock_spd_release,
	};
	struct sk_buff *frag_iter;
	struct sock *sk = skb->sk;
	int ret = 0;

	if (splice_grow_spd(pipe, &spd))
		return -ENOMEM;

	/*
	 * __skb_splice_bits() only fails if the output has no room left,
	 * so no point in going over the frag_list for the error case.
	 */
	if (__skb_splice_bits(skb, pipe, &offset, &tlen, &spd, sk))
		goto done;
	else if (!tlen)
		goto done;

	/*
	 * now see if we have a frag_list to map
	 */
	skb_walk_frags(skb, frag_iter) {
		if (!tlen)
			break;
		if (__skb_splice_bits(frag_iter, pipe, &offset, &tlen, &spd, sk))
			break;
	}

done:
	if (spd.nr_pages) {
		/*
		 * Drop the socket lock, otherwise we have reverse
		 * locking dependencies between sk_lock and i_mutex
		 * here as compared to sendfile(). We enter here
		 * with the socket lock held, and splice_to_pipe() will
		 * grab the pipe inode lock. For sendfile() emulation,
		 * we call into ->sendpage() with the i_mutex lock held
		 * and networking will grab the socket lock.
		 */
		release_sock(sk);
		ret = splice_to_pipe(pipe, &spd);
		lock_sock(sk);
	}

	splice_shrink_spd(pipe, &spd);
	return ret;
}

/**
 *	skb_store_bits - store bits from kernel buffer to skb
 *	@skb: destination buffer
 *	@offset: offset in destination
 *	@from: source buffer
 *	@len: number of bytes to copy
 *
 *	Copy the specified number of bytes from the source buffer to the
 *	destination skb.  This function handles all the messy bits of
 *	traversing fragment lists and such.
 */

int skb_store_bits(struct sk_buff *skb, int offset, const void *from, int len)
{
	int start = skb_headlen(skb);
	struct sk_buff *frag_iter;
	int i, copy;

	if (offset > (int)skb->len - len)
		goto fault;

	if ((copy = start - offset) > 0) {
		if (copy > len)
			copy = len;
		skb_copy_to_linear_data_offset(skb, offset, from, copy);
		if ((len -= copy) == 0)
			return 0;
		offset += copy;
		from += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		int end;

		WARN_ON(start > offset + len);

		end = start + frag->size;
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;

			vaddr = kmap_skb_frag(frag);
			memcpy(vaddr + frag->page_offset + offset - start,
			       from, copy);
			kunmap_skb_frag(vaddr);

			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			from += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			if (skb_store_bits(frag_iter, offset - start,
					   from, copy))
				goto fault;
			if ((len -= copy) == 0)
				return 0;
			offset += copy;
			from += copy;
		}
		start = end;
	}
	if (!len)
		return 0;

fault:
	return -EFAULT;
}
EXPORT_SYMBOL(skb_store_bits);

/* Checksum skb data. */

__wsum skb_checksum(const struct sk_buff *skb, int offset,
			  int len, __wsum csum)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int pos = 0;

	/* Checksum header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
		csum = csum_partial(skb->data + offset, copy, csum);
		if ((len -= copy) == 0)
			return csum;
		offset += copy;
		pos	= copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			__wsum csum2;
			u8 *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			vaddr = kmap_skb_frag(frag);
			csum2 = csum_partial(vaddr + frag->page_offset +
					     offset - start, copy, 0);
			kunmap_skb_frag(vaddr);
			csum = csum_block_add(csum, csum2, pos);
			if (!(len -= copy))
				return csum;
			offset += copy;
			pos    += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			__wsum csum2;
			if (copy > len)
				copy = len;
			csum2 = skb_checksum(frag_iter, offset - start,
					     copy, 0);
			csum = csum_block_add(csum, csum2, pos);
			if ((len -= copy) == 0)
				return csum;
			offset += copy;
			pos    += copy;
		}
		start = end;
	}
	BUG_ON(len);

	return csum;
}
EXPORT_SYMBOL(skb_checksum);

/* Both of above in one bottle. */

__wsum skb_copy_and_csum_bits(const struct sk_buff *skb, int offset,
				    u8 *to, int len, __wsum csum)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int pos = 0;

	/* Copy header. */
	if (copy > 0) {
		if (copy > len)
			copy = len;
		csum = csum_partial_copy_nocheck(skb->data + offset, to,
						 copy, csum);
		if ((len -= copy) == 0)
			return csum;
		offset += copy;
		to     += copy;
		pos	= copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			__wsum csum2;
			u8 *vaddr;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			vaddr = kmap_skb_frag(frag);
			csum2 = csum_partial_copy_nocheck(vaddr +
							  frag->page_offset +
							  offset - start, to,
							  copy, 0);
			kunmap_skb_frag(vaddr);
			csum = csum_block_add(csum, csum2, pos);
			if (!(len -= copy))
				return csum;
			offset += copy;
			to     += copy;
			pos    += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		__wsum csum2;
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			csum2 = skb_copy_and_csum_bits(frag_iter,
						       offset - start,
						       to, copy, 0);
			csum = csum_block_add(csum, csum2, pos);
			if ((len -= copy) == 0)
				return csum;
			offset += copy;
			to     += copy;
			pos    += copy;
		}
		start = end;
	}
	BUG_ON(len);
	return csum;
}
EXPORT_SYMBOL(skb_copy_and_csum_bits);

void skb_copy_and_csum_dev(const struct sk_buff *skb, u8 *to)
{
	__wsum csum;
	long csstart;

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		csstart = skb->csum_start - skb_headroom(skb);
	else
		csstart = skb_headlen(skb);

	BUG_ON(csstart > skb_headlen(skb));

	skb_copy_from_linear_data(skb, to, csstart);

	csum = 0;
	if (csstart != skb->len)
		csum = skb_copy_and_csum_bits(skb, csstart, to + csstart,
					      skb->len - csstart, 0);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		long csstuff = csstart + skb->csum_offset;

		*((__sum16 *)(to + csstuff)) = csum_fold(csum);
	}
}
EXPORT_SYMBOL(skb_copy_and_csum_dev);

/**
 *	skb_dequeue - remove from the head of the queue
 *	@list: list to dequeue from
 *
 *	Remove the head of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The head item is
 *	returned or %NULL if the list is empty.
 */
    //从list队列取出头部skb
struct sk_buff *skb_dequeue(struct sk_buff_head *list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, flags);
	result = __skb_dequeue(list);
	spin_unlock_irqrestore(&list->lock, flags);
	return result;
}
EXPORT_SYMBOL(skb_dequeue);

/**
 *	skb_dequeue_tail - remove from the tail of the queue
 *	@list: list to dequeue from
 *
 *	Remove the tail of the list. The list lock is taken so the function
 *	may be used safely with other locking list functions. The tail item is
 *	returned or %NULL if the list is empty.
 */
struct sk_buff *skb_dequeue_tail(struct sk_buff_head *list)
{
	unsigned long flags;
	struct sk_buff *result;

	spin_lock_irqsave(&list->lock, flags);
	result = __skb_dequeue_tail(list);
	spin_unlock_irqrestore(&list->lock, flags);
	return result;
}
EXPORT_SYMBOL(skb_dequeue_tail);

/**
 *	skb_queue_purge - empty a list
 *	@list: list to empty
 *
 *	Delete all buffers on an &sk_buff list. Each buffer is removed from
 *	the list and one reference dropped. This function takes the list
 *	lock and is atomic with respect to other list locking functions.
 *///情况链表中的所有SKB，并释放其中的空间
void skb_queue_purge(struct sk_buff_head *list)
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(list)) != NULL)
		kfree_skb(skb);
}
EXPORT_SYMBOL(skb_queue_purge);

/**
 *	skb_queue_head - queue a buffer at the list head
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the start of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_queue_head(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_head(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}
EXPORT_SYMBOL(skb_queue_head);

/**
 *	skb_queue_tail - queue a buffer at the list tail
 *	@list: list to use
 *	@newsk: buffer to queue
 *
 *	Queue a buffer at the tail of the list. This function takes the
 *	list lock and can be used safely with other locking &sk_buff functions
 *	safely.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_queue_tail(struct sk_buff_head *list, struct sk_buff *newsk)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_tail(list, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}
EXPORT_SYMBOL(skb_queue_tail);

/**
 *	skb_unlink	-	remove a buffer from a list
 *	@skb: buffer to remove
 *	@list: list to use
 *
 *	Remove a packet from a list. The list locks are taken and this
 *	function is atomic with respect to other list locked calls
 *
 *	You must know what list the SKB is on.
 */
void skb_unlink(struct sk_buff *skb, struct sk_buff_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_unlink(skb, list);
	spin_unlock_irqrestore(&list->lock, flags);
}
EXPORT_SYMBOL(skb_unlink);

/**
 *	skb_append	-	append a buffer
 *	@old: buffer to insert after
 *	@newsk: buffer to insert
 *	@list: list to use
 *
 *	Place a packet after a given packet in a list. The list locks are taken
 *	and this function is atomic with respect to other list locked calls.
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_append(struct sk_buff *old, struct sk_buff *newsk, struct sk_buff_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_queue_after(list, old, newsk);
	spin_unlock_irqrestore(&list->lock, flags);
}
EXPORT_SYMBOL(skb_append);

/**
 *	skb_insert	-	insert a buffer
 *	@old: buffer to insert before
 *	@newsk: buffer to insert
 *	@list: list to use
 *
 *	Place a packet before a given packet in a list. The list locks are
 * 	taken and this function is atomic with respect to other list locked
 *	calls.
 *
 *	A buffer cannot be placed on two lists at the same time.
 */
void skb_insert(struct sk_buff *old, struct sk_buff *newsk, struct sk_buff_head *list)
{
	unsigned long flags;

	spin_lock_irqsave(&list->lock, flags);
	__skb_insert(newsk, old->prev, old, list);
	spin_unlock_irqrestore(&list->lock, flags);
}
EXPORT_SYMBOL(skb_insert);

static inline void skb_split_inside_header(struct sk_buff *skb,
					   struct sk_buff* skb1,
					   const u32 len, const int pos)
{
	int i;

	skb_copy_from_linear_data_offset(skb, len, skb_put(skb1, pos - len),
					 pos - len);
	/* And move data appendix as is. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
		skb_shinfo(skb1)->frags[i] = skb_shinfo(skb)->frags[i];

	skb_shinfo(skb1)->nr_frags = skb_shinfo(skb)->nr_frags;
	skb_shinfo(skb)->nr_frags  = 0;
	skb1->data_len		   = skb->data_len;
	skb1->len		   += skb1->data_len;
	skb->data_len		   = 0;
	skb->len		   = len;
	skb_set_tail_pointer(skb, len);
}

static inline void skb_split_no_header(struct sk_buff *skb,
				       struct sk_buff* skb1,
				       const u32 len, int pos)
{
	int i, k = 0;
	const int nfrags = skb_shinfo(skb)->nr_frags;

	skb_shinfo(skb)->nr_frags = 0;
	skb1->len		  = skb1->data_len = skb->len - len;
	skb->len		  = len;
	skb->data_len		  = len - pos;

	for (i = 0; i < nfrags; i++) {
		int size = skb_shinfo(skb)->frags[i].size;

		if (pos + size > len) {
			skb_shinfo(skb1)->frags[k] = skb_shinfo(skb)->frags[i];

			if (pos < len) {
				/* Split frag.
				 * We have two variants in this case:
				 * 1. Move all the frag to the second
				 *    part, if it is possible. F.e.
				 *    this approach is mandatory for TUX,
				 *    where splitting is expensive.
				 * 2. Split is accurately. We make this.
				 */
				get_page(skb_shinfo(skb)->frags[i].page);
				skb_shinfo(skb1)->frags[0].page_offset += len - pos;
				skb_shinfo(skb1)->frags[0].size -= len - pos;
				skb_shinfo(skb)->frags[i].size	= len - pos;
				skb_shinfo(skb)->nr_frags++;
			}
			k++;
		} else
			skb_shinfo(skb)->nr_frags++;
		pos += size;
	}
	skb_shinfo(skb1)->nr_frags = k;
}

/**
 * skb_split - Split fragmented skb to two parts at length len.
 * @skb: the buffer to split
 * @skb1: the buffer to receive the second part
 * @len: new length for skb
 *///skb为待拆分的skb,skb1为拆分后产生的新skb，len为源skb拆分后留下的数据长度  参考44页码
 //当拆分数据的长度小于data区长度时，直接拆分data区即可，也就是如果源skb中的数据区长度大于len，则源skb中剩下的skb长度为数据区前面的len字节。
 //如果len大于数据区长度。则skb中最后的数据为线性data区数据，还会有一部分分片区数据，分片中剩下的是第一个frags中的分片数据剩余部分  
 //参考图3-29   45页码
/*
  * skb_split()可根据指定长度拆分SKB，使得原SKB中的数据长度
  * 为指定的长度，而剩下的数据则保存到拆分得到的
  * SKB中。
  * 由于SKB中支持线性存储和聚合分散I/O存储，因此
  * 在拆分过程中需要考虑这些情况。当拆分数据
  * 的长度小于线性数据长度时比较容易处理，直接拆分
  * 线性数据区即可。
  * 参数skb为待拆分的SKB，skb1为拆分得到的SKB，len为
  * 拆分后原SKB中数据的长度。
  * 若拆分数据的长度大于线性数据长度，则需要拆分
  * 非线性区域中的数据
  */
void skb_split(struct sk_buff *skb, struct sk_buff *skb1, const u32 len)
{
	int pos = skb_headlen(skb);//线性缓冲区的长度

	if (len < pos)	/* Split line is inside header. */ 
		skb_split_inside_header(skb, skb1, len, pos);//从skb的线性缓冲区中拆分pos-len字节到skb1的线性缓冲区中见樊东东上P44P45
	else		/* Second chunk has no header, nothing to copy. */
		skb_split_no_header(skb, skb1, len, pos); //从skb分散聚合I/O页中拆分一部分到skb1中 见樊东东上P44P45
}
EXPORT_SYMBOL(skb_split);

/* Shifting from/to a cloned skb is a no-go.
 *
 * Caller cannot keep skb_shinfo related pointers past calling here!
 */
static int skb_prepare_for_shift(struct sk_buff *skb)
{
	return skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}

/**
 * skb_shift - Shifts paged data partially from skb to another
 * @tgt: buffer into which tail data gets added
 * @skb: buffer from which the paged data comes from
 * @shiftlen: shift up to this many bytes
 *
 * Attempts to shift up to shiftlen worth of bytes, which may be less than
 * the length of the skb, from tgt to skb. Returns number bytes shifted.
 * It's up to caller to free skb if everything was shifted.
 *
 * If @tgt runs out of frags, the whole operation is aborted.
 *
 * Skb cannot include anything else but paged data while tgt is allowed
 * to have non-paged data as well.
 *
 * TODO: full sized shift could be optimized but that would need
 * specialized skb free'er to handle frags without up-to-date nr_frags.
 */
int skb_shift(struct sk_buff *tgt, struct sk_buff *skb, int shiftlen)
{
	int from, to, merge, todo;
	struct skb_frag_struct *fragfrom, *fragto;

	BUG_ON(shiftlen > skb->len);
	BUG_ON(skb_headlen(skb));	/* Would corrupt stream */

	todo = shiftlen;
	from = 0;
	to = skb_shinfo(tgt)->nr_frags;
	fragfrom = &skb_shinfo(skb)->frags[from];

	/* Actual merge is delayed until the point when we know we can
	 * commit all, so that we don't have to undo partial changes
	 */
	if (!to ||
	    !skb_can_coalesce(tgt, to, fragfrom->page, fragfrom->page_offset)) {
		merge = -1;
	} else {
		merge = to - 1;

		todo -= fragfrom->size;
		if (todo < 0) {
			if (skb_prepare_for_shift(skb) ||
			    skb_prepare_for_shift(tgt))
				return 0;

			/* All previous frag pointers might be stale! */
			fragfrom = &skb_shinfo(skb)->frags[from];
			fragto = &skb_shinfo(tgt)->frags[merge];

			fragto->size += shiftlen;
			fragfrom->size -= shiftlen;
			fragfrom->page_offset += shiftlen;

			goto onlymerged;
		}

		from++;
	}

	/* Skip full, not-fitting skb to avoid expensive operations */
	if ((shiftlen == skb->len) &&
	    (skb_shinfo(skb)->nr_frags - from) > (MAX_SKB_FRAGS - to))
		return 0;

	if (skb_prepare_for_shift(skb) || skb_prepare_for_shift(tgt))
		return 0;

	while ((todo > 0) && (from < skb_shinfo(skb)->nr_frags)) {
		if (to == MAX_SKB_FRAGS)
			return 0;

		fragfrom = &skb_shinfo(skb)->frags[from];
		fragto = &skb_shinfo(tgt)->frags[to];

		if (todo >= fragfrom->size) {
			*fragto = *fragfrom;
			todo -= fragfrom->size;
			from++;
			to++;

		} else {
			get_page(fragfrom->page);
			fragto->page = fragfrom->page;
			fragto->page_offset = fragfrom->page_offset;
			fragto->size = todo;

			fragfrom->page_offset += todo;
			fragfrom->size -= todo;
			todo = 0;

			to++;
			break;
		}
	}

	/* Ready to "commit" this state change to tgt */
	skb_shinfo(tgt)->nr_frags = to;

	if (merge >= 0) {
		fragfrom = &skb_shinfo(skb)->frags[0];
		fragto = &skb_shinfo(tgt)->frags[merge];

		fragto->size += fragfrom->size;
		put_page(fragfrom->page);
	}

	/* Reposition in the original skb */
	to = 0;
	while (from < skb_shinfo(skb)->nr_frags)
		skb_shinfo(skb)->frags[to++] = skb_shinfo(skb)->frags[from++];
	skb_shinfo(skb)->nr_frags = to;

	BUG_ON(todo > 0 && !skb_shinfo(skb)->nr_frags);

onlymerged:
	/* Most likely the tgt won't ever need its checksum anymore, skb on
	 * the other hand might need it if it needs to be resent
	 */
	tgt->ip_summed = CHECKSUM_PARTIAL;
	skb->ip_summed = CHECKSUM_PARTIAL;

	/* Yak, is it really working this way? Some helper please? */
	skb->len -= shiftlen;
	skb->data_len -= shiftlen;
	skb->truesize -= shiftlen;
	tgt->len += shiftlen;
	tgt->data_len += shiftlen;
	tgt->truesize += shiftlen;

	return shiftlen;
}

/**
 * skb_prepare_seq_read - Prepare a sequential read of skb data
 * @skb: the buffer to read
 * @from: lower offset of data to be read
 * @to: upper offset of data to be read
 * @st: state variable
 *
 * Initializes the specified state variable. Must be called before
 * invoking skb_seq_read() for the first time.
 */
void skb_prepare_seq_read(struct sk_buff *skb, unsigned int from,
			  unsigned int to, struct skb_seq_state *st)
{
	st->lower_offset = from;
	st->upper_offset = to;
	st->root_skb = st->cur_skb = skb;
	st->frag_idx = st->stepped_offset = 0;
	st->frag_data = NULL;
}
EXPORT_SYMBOL(skb_prepare_seq_read);

/**
 * skb_seq_read - Sequentially read skb data
 * @consumed: number of bytes consumed by the caller so far
 * @data: destination pointer for data to be returned
 * @st: state variable
 *
 * Reads a block of skb data at &consumed relative to the
 * lower offset specified to skb_prepare_seq_read(). Assigns
 * the head of the data block to &data and returns the length
 * of the block or 0 if the end of the skb data or the upper
 * offset has been reached.
 *
 * The caller is not required to consume all of the data
 * returned, i.e. &consumed is typically set to the number
 * of bytes already consumed and the next call to
 * skb_seq_read() will return the remaining part of the block.
 *
 * Note 1: The size of each block of data returned can be arbitary,
 *       this limitation is the cost for zerocopy seqeuental
 *       reads of potentially non linear data.
 *
 * Note 2: Fragment lists within fragments are not implemented
 *       at the moment, state->root_skb could be replaced with
 *       a stack for this purpose.
 */
unsigned int skb_seq_read(unsigned int consumed, const u8 **data,
			  struct skb_seq_state *st)
{
	unsigned int block_limit, abs_offset = consumed + st->lower_offset;
	skb_frag_t *frag;

	if (unlikely(abs_offset >= st->upper_offset))
		return 0;

next_skb:
	block_limit = skb_headlen(st->cur_skb) + st->stepped_offset;

	if (abs_offset < block_limit && !st->frag_data) {
		*data = st->cur_skb->data + (abs_offset - st->stepped_offset);
		return block_limit - abs_offset;
	}

	if (st->frag_idx == 0 && !st->frag_data)
		st->stepped_offset += skb_headlen(st->cur_skb);

	while (st->frag_idx < skb_shinfo(st->cur_skb)->nr_frags) {
		frag = &skb_shinfo(st->cur_skb)->frags[st->frag_idx];
		block_limit = frag->size + st->stepped_offset;

		if (abs_offset < block_limit) {
			if (!st->frag_data)
				st->frag_data = kmap_skb_frag(frag);

			*data = (u8 *) st->frag_data + frag->page_offset +
				(abs_offset - st->stepped_offset);

			return block_limit - abs_offset;
		}

		if (st->frag_data) {
			kunmap_skb_frag(st->frag_data);
			st->frag_data = NULL;
		}

		st->frag_idx++;
		st->stepped_offset += frag->size;
	}

	if (st->frag_data) {
		kunmap_skb_frag(st->frag_data);
		st->frag_data = NULL;
	}

	if (st->root_skb == st->cur_skb && skb_has_frags(st->root_skb)) {
		st->cur_skb = skb_shinfo(st->root_skb)->frag_list;
		st->frag_idx = 0;
		goto next_skb;
	} else if (st->cur_skb->next) {
		st->cur_skb = st->cur_skb->next;
		st->frag_idx = 0;
		goto next_skb;
	}

	return 0;
}
EXPORT_SYMBOL(skb_seq_read);

/**
 * skb_abort_seq_read - Abort a sequential read of skb data
 * @st: state variable
 *
 * Must be called if skb_seq_read() was not called until it
 * returned 0.
 */
void skb_abort_seq_read(struct skb_seq_state *st)
{
	if (st->frag_data)
		kunmap_skb_frag(st->frag_data);
}
EXPORT_SYMBOL(skb_abort_seq_read);

#define TS_SKB_CB(state)	((struct skb_seq_state *) &((state)->cb))

static unsigned int skb_ts_get_next_block(unsigned int offset, const u8 **text,
					  struct ts_config *conf,
					  struct ts_state *state)
{
	return skb_seq_read(offset, text, TS_SKB_CB(state));
}

static void skb_ts_finish(struct ts_config *conf, struct ts_state *state)
{
	skb_abort_seq_read(TS_SKB_CB(state));
}

/**
 * skb_find_text - Find a text pattern in skb data
 * @skb: the buffer to look in
 * @from: search offset
 * @to: search limit
 * @config: textsearch configuration
 * @state: uninitialized textsearch state variable
 *
 * Finds a pattern in the skb data according to the specified
 * textsearch configuration. Use textsearch_next() to retrieve
 * subsequent occurrences of the pattern. Returns the offset
 * to the first occurrence or UINT_MAX if no match was found.
 */
unsigned int skb_find_text(struct sk_buff *skb, unsigned int from,
			   unsigned int to, struct ts_config *config,
			   struct ts_state *state)
{
	unsigned int ret;

	config->get_next_block = skb_ts_get_next_block;
	config->finish = skb_ts_finish;

	skb_prepare_seq_read(skb, from, to, TS_SKB_CB(state));

	ret = textsearch_find(config, state);
	return (ret <= to - from ? ret : UINT_MAX);
}
EXPORT_SYMBOL(skb_find_text);

/**
 * skb_append_datato_frags: - append the user data to a skb
 * @sk: sock  structure
 * @skb: skb structure to be appened with user data.
 * @getfrag: call back function to be used for getting the user data
 * @from: pointer to user message iov
 * @length: length of the iov message
 *
 * Description: This procedure append the user data in the fragment part
 * of the skb if any page alloc fails user this procedure returns  -ENOMEM
 */
int skb_append_datato_frags(struct sock *sk, struct sk_buff *skb,
			int (*getfrag)(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			void *from, int length)
{
	int frg_cnt = 0;
	skb_frag_t *frag = NULL;
	struct page *page = NULL;
	int copy, left;
	int offset = 0;
	int ret;

	do {
		/* Return error if we don't have space for new frag */
		frg_cnt = skb_shinfo(skb)->nr_frags;
		if (frg_cnt >= MAX_SKB_FRAGS)
			return -EFAULT;

		/* allocate a new page for next frag */
		page = alloc_pages(sk->sk_allocation, 0);

		/* If alloc_page fails just return failure and caller will
		 * free previous allocated pages by doing kfree_skb()
		 */
		if (page == NULL)
			return -ENOMEM;

		/* initialize the next frag */
		sk->sk_sndmsg_page = page;
		sk->sk_sndmsg_off = 0;
		skb_fill_page_desc(skb, frg_cnt, page, 0, 0);
		skb->truesize += PAGE_SIZE;
		atomic_add(PAGE_SIZE, &sk->sk_wmem_alloc);

		/* get the new initialized frag */
		frg_cnt = skb_shinfo(skb)->nr_frags;
		frag = &skb_shinfo(skb)->frags[frg_cnt - 1];

		/* copy the user data to page */
		left = PAGE_SIZE - frag->page_offset;
		copy = (length > left)? left : length;

		ret = getfrag(from, (page_address(frag->page) +
			    frag->page_offset + frag->size),
			    offset, copy, 0, skb);
		if (ret < 0)
			return -EFAULT;

		/* copy was successful so update the size parameters */
		sk->sk_sndmsg_off += copy;
		frag->size += copy;
		skb->len += copy;
		skb->data_len += copy;
		offset += copy;
		length -= copy;

	} while (length > 0);

	return 0;
}
EXPORT_SYMBOL(skb_append_datato_frags);

/**
 *	skb_pull_rcsum - pull skb and update receive checksum
 *	@skb: buffer to update
 *	@len: length of data pulled
 *
 *	This function performs an skb_pull on the packet and updates
 *	the CHECKSUM_COMPLETE checksum.  It should be used on
 *	receive path processing instead of skb_pull unless you know
 *	that the checksum difference is zero (e.g., a valid IP header)
 *	or you are setting ip_summed to CHECKSUM_NONE.
 */
unsigned char *skb_pull_rcsum(struct sk_buff *skb, unsigned int len)
{
	BUG_ON(len > skb->len);
	skb->len -= len;
	BUG_ON(skb->len < skb->data_len);
	skb_postpull_rcsum(skb, skb->data, len);
	return skb->data += len;
}

EXPORT_SYMBOL_GPL(skb_pull_rcsum);

/**
 *	skb_segment - Perform protocol segmentation on skb.
 *	@skb: buffer to segment
 *	@features: features for the output path (see dev->features)
 *
 *	This function performs segmentation on the given skb.  It returns
 *	a pointer to the first in a list of new skbs for the segments.
 *	In case of error it returns ERR_PTR(err).
 */
struct sk_buff *skb_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *fskb = skb_shinfo(skb)->frag_list;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	unsigned int doffset = skb->data - skb_mac_header(skb);
	unsigned int offset = doffset;
	unsigned int headroom;
	unsigned int len;
	int sg = features & NETIF_F_SG;
	int nfrags = skb_shinfo(skb)->nr_frags;
	int err = -ENOMEM;
	int i = 0;
	int pos;

	__skb_push(skb, doffset);
	headroom = skb_headroom(skb);
	pos = skb_headlen(skb);

	do {
		struct sk_buff *nskb;
		skb_frag_t *frag;
		int hsize;
		int size;

		len = skb->len - offset;
		if (len > mss)
			len = mss;

		hsize = skb_headlen(skb) - offset;
		if (hsize < 0)
			hsize = 0;
		if (hsize > len || !sg)
			hsize = len;

		if (!hsize && i >= nfrags) {
			BUG_ON(fskb->len != len);

			pos += len;
			nskb = skb_clone(fskb, GFP_ATOMIC);
			fskb = fskb->next;

			if (unlikely(!nskb))
				goto err;

			hsize = skb_end_pointer(nskb) - nskb->head;
			if (skb_cow_head(nskb, doffset + headroom)) {
				kfree_skb(nskb);
				goto err;
			}

			nskb->truesize += skb_end_pointer(nskb) - nskb->head -
					  hsize;
			skb_release_head_state(nskb);
			__skb_push(nskb, doffset);
		} else {
			nskb = alloc_skb(hsize + doffset + headroom,
					 GFP_ATOMIC);

			if (unlikely(!nskb))
				goto err;

			skb_reserve(nskb, headroom);
			__skb_put(nskb, doffset);
		}

		if (segs)
			tail->next = nskb;
		else
			segs = nskb;
		tail = nskb;

		__copy_skb_header(nskb, skb);
		nskb->mac_len = skb->mac_len;

		/* nskb and skb might have different headroom */
		if (nskb->ip_summed == CHECKSUM_PARTIAL)
			nskb->csum_start += skb_headroom(nskb) - headroom;

		skb_reset_mac_header(nskb);
		skb_set_network_header(nskb, skb->mac_len);
		nskb->transport_header = (nskb->network_header +
					  skb_network_header_len(skb));
		skb_copy_from_linear_data(skb, nskb->data, doffset);

		if (fskb != skb_shinfo(skb)->frag_list)
			continue;

		if (!sg) {
			nskb->ip_summed = CHECKSUM_NONE;
			nskb->csum = skb_copy_and_csum_bits(skb, offset,
							    skb_put(nskb, len),
							    len, 0);
			continue;
		}

		frag = skb_shinfo(nskb)->frags;

		skb_copy_from_linear_data_offset(skb, offset,
						 skb_put(nskb, hsize), hsize);

		while (pos < offset + len && i < nfrags) {
			*frag = skb_shinfo(skb)->frags[i];
			get_page(frag->page);
			size = frag->size;

			if (pos < offset) {
				frag->page_offset += offset - pos;
				frag->size -= offset - pos;
			}

			skb_shinfo(nskb)->nr_frags++;

			if (pos + size <= offset + len) {
				i++;
				pos += size;
			} else {
				frag->size -= pos + size - (offset + len);
				goto skip_fraglist;
			}

			frag++;
		}

		if (pos < offset + len) {
			struct sk_buff *fskb2 = fskb;

			BUG_ON(pos + fskb->len != offset + len);

			pos += fskb->len;
			fskb = fskb->next;

			if (fskb2->next) {
				fskb2 = skb_clone(fskb2, GFP_ATOMIC);
				if (!fskb2)
					goto err;
			} else
				skb_get(fskb2);

			SKB_FRAG_ASSERT(nskb);
			skb_shinfo(nskb)->frag_list = fskb2;
		}

skip_fraglist:
		nskb->data_len = len - hsize;
		nskb->len += nskb->data_len;
		nskb->truesize += nskb->data_len;
	} while ((offset += len) < skb->len);

	return segs;

err:
	while ((skb = segs)) {
		segs = skb->next;
		kfree_skb(skb);
	}
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(skb_segment);

int skb_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct sk_buff *p = *head;
	struct sk_buff *nskb;
	struct skb_shared_info *skbinfo = skb_shinfo(skb);
	struct skb_shared_info *pinfo = skb_shinfo(p);
	unsigned int headroom;
	unsigned int len = skb_gro_len(skb);
	unsigned int offset = skb_gro_offset(skb);
	unsigned int headlen = skb_headlen(skb);

	if (p->len + len >= 65536)
		return -E2BIG;

	if (pinfo->frag_list)
		goto merge;
	else if (headlen <= offset) {
		skb_frag_t *frag;
		skb_frag_t *frag2;
		int i = skbinfo->nr_frags;
		int nr_frags = pinfo->nr_frags + i;

		offset -= headlen;

		if (nr_frags > MAX_SKB_FRAGS)
			return -E2BIG;

		pinfo->nr_frags = nr_frags;
		skbinfo->nr_frags = 0;

		frag = pinfo->frags + nr_frags;
		frag2 = skbinfo->frags + i;
		do {
			*--frag = *--frag2;
		} while (--i);

		frag->page_offset += offset;
		frag->size -= offset;

		skb->truesize -= skb->data_len;
		skb->len -= skb->data_len;
		skb->data_len = 0;

		NAPI_GRO_CB(skb)->free = 1;
		goto done;
	} else if (skb_gro_len(p) != pinfo->gso_size)
		return -E2BIG;

	headroom = skb_headroom(p);
	nskb = alloc_skb(headroom + skb_gro_offset(p), GFP_ATOMIC);
	if (unlikely(!nskb))
		return -ENOMEM;

	__copy_skb_header(nskb, p);
	nskb->mac_len = p->mac_len;

	skb_reserve(nskb, headroom);
	__skb_put(nskb, skb_gro_offset(p));

	skb_set_mac_header(nskb, skb_mac_header(p) - p->data);
	skb_set_network_header(nskb, skb_network_offset(p));
	skb_set_transport_header(nskb, skb_transport_offset(p));

	__skb_pull(p, skb_gro_offset(p));
	memcpy(skb_mac_header(nskb), skb_mac_header(p),
	       p->data - skb_mac_header(p));

	*NAPI_GRO_CB(nskb) = *NAPI_GRO_CB(p);
	skb_shinfo(nskb)->frag_list = p;
	skb_shinfo(nskb)->gso_size = pinfo->gso_size;
	pinfo->gso_size = 0;
	skb_header_release(p);
	nskb->prev = p;

	nskb->data_len += p->len;
	nskb->truesize += p->len;
	nskb->len += p->len;

	*head = nskb;
	nskb->next = p->next;
	p->next = NULL;

	p = nskb;

merge:
	if (offset > headlen) {
		skbinfo->frags[0].page_offset += offset - headlen;
		skbinfo->frags[0].size -= offset - headlen;
		offset = headlen;
	}

	__skb_pull(skb, offset);

	p->prev->next = skb;
	p->prev = skb;
	skb_header_release(skb);

done:
	NAPI_GRO_CB(p)->count++;
	p->data_len += len;
	p->truesize += len;
	p->len += len;

	NAPI_GRO_CB(skb)->same_flow = 1;
	return 0;
}
EXPORT_SYMBOL_GPL(skb_gro_receive);

void __init skb_init(void)
{
	skbuff_head_cache = kmem_cache_create("skbuff_head_cache",
					      sizeof(struct sk_buff),
					      0,
					      SLAB_HWCACHE_ALIGN|SLAB_PANIC,
					      NULL);
	skbuff_fclone_cache = kmem_cache_create("skbuff_fclone_cache",
						(2*sizeof(struct sk_buff)) +       //这里加了个sizeof(atomic_t)的原因是，用这个来表示引用计数，参考skb_clone
						sizeof(atomic_t),
						0,
						SLAB_HWCACHE_ALIGN|SLAB_PANIC,
						NULL);
}

/**
 *	skb_to_sgvec - Fill a scatter-gather list from a socket buffer
 *	@skb: Socket buffer containing the buffers to be mapped
 *	@sg: The scatter-gather list to map into
 *	@offset: The offset into the buffer's contents to start mapping
 *	@len: Length of buffer space to be mapped
 *
 *	Fill the specified scatter-gather list with mappings/pointers into a
 *	region of the buffer space attached to a socket buffer.
 */
static int
__skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len)
{
	int start = skb_headlen(skb);
	int i, copy = start - offset;
	struct sk_buff *frag_iter;
	int elt = 0;

	if (copy > 0) {
		if (copy > len)
			copy = len;
		sg_set_buf(sg, skb->data + offset, copy);
		elt++;
		if ((len -= copy) == 0)
			return elt;
		offset += copy;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;

		WARN_ON(start > offset + len);

		end = start + skb_shinfo(skb)->frags[i].size;
		if ((copy = end - offset) > 0) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

			if (copy > len)
				copy = len;
			sg_set_page(&sg[elt], frag->page, copy,
					frag->page_offset+offset-start);
			elt++;
			if (!(len -= copy))
				return elt;
			offset += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			elt += __skb_to_sgvec(frag_iter, sg+elt, offset - start,
					      copy);
			if ((len -= copy) == 0)
				return elt;
			offset += copy;
		}
		start = end;
	}
	BUG_ON(len);
	return elt;
}

int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len)
{
	int nsg = __skb_to_sgvec(skb, sg, offset, len);

	sg_mark_end(&sg[nsg - 1]);

	return nsg;
}
EXPORT_SYMBOL_GPL(skb_to_sgvec);

/**
 *	skb_cow_data - Check that a socket buffer's data buffers are writable
 *	@skb: The socket buffer to check.
 *	@tailbits: Amount of trailing space to be added
 *	@trailer: Returned pointer to the skb where the @tailbits space begins
 *
 *	Make sure that the data buffers attached to a socket buffer are
 *	writable. If they are not, private copies are made of the data buffers
 *	and the socket buffer is set to use these instead.
 *
 *	If @tailbits is given, make sure that there is space to write @tailbits
 *	bytes of data beyond current end of socket buffer.  @trailer will be
 *	set to point to the skb in which this space begins.
 *
 *	The number of scatterlist elements required to completely map the
 *	COW'd and extended socket buffer will be returned.
 */
int skb_cow_data(struct sk_buff *skb, int tailbits, struct sk_buff **trailer)
{
	int copyflag;
	int elt;
	struct sk_buff *skb1, **skb_p;

	/* If skb is cloned or its head is paged, reallocate
	 * head pulling out all the pages (pages are considered not writable
	 * at the moment even if they are anonymous).
	 */
	if ((skb_cloned(skb) || skb_shinfo(skb)->nr_frags) &&
	    __pskb_pull_tail(skb, skb_pagelen(skb)-skb_headlen(skb)) == NULL)
		return -ENOMEM;

	/* Easy case. Most of packets will go this way. */
	if (!skb_has_frags(skb)) {
		/* A little of trouble, not enough of space for trailer.
		 * This should not happen, when stack is tuned to generate
		 * good frames. OK, on miss we reallocate and reserve even more
		 * space, 128 bytes is fair. */

		if (skb_tailroom(skb) < tailbits &&
		    pskb_expand_head(skb, 0, tailbits-skb_tailroom(skb)+128, GFP_ATOMIC))
			return -ENOMEM;

		/* Voila! */
		*trailer = skb;
		return 1;
	}

	/* Misery. We are in troubles, going to mincer fragments... */

	elt = 1;
	skb_p = &skb_shinfo(skb)->frag_list;
	copyflag = 0;

	while ((skb1 = *skb_p) != NULL) {
		int ntail = 0;

		/* The fragment is partially pulled by someone,
		 * this can happen on input. Copy it and everything
		 * after it. */

		if (skb_shared(skb1))
			copyflag = 1;

		/* If the skb is the last, worry about trailer. */

		if (skb1->next == NULL && tailbits) {
			if (skb_shinfo(skb1)->nr_frags ||
			    skb_has_frags(skb1) ||
			    skb_tailroom(skb1) < tailbits)
				ntail = tailbits + 128;
		}

		if (copyflag ||
		    skb_cloned(skb1) ||
		    ntail ||
		    skb_shinfo(skb1)->nr_frags ||
		    skb_has_frags(skb1)) {
			struct sk_buff *skb2;

			/* Fuck, we are miserable poor guys... */
			if (ntail == 0)
				skb2 = skb_copy(skb1, GFP_ATOMIC);
			else
				skb2 = skb_copy_expand(skb1,
						       skb_headroom(skb1),
						       ntail,
						       GFP_ATOMIC);
			if (unlikely(skb2 == NULL))
				return -ENOMEM;

			if (skb1->sk)
				skb_set_owner_w(skb2, skb1->sk);

			/* Looking around. Are we still alive?
			 * OK, link new skb, drop old one */

			skb2->next = skb1->next;
			*skb_p = skb2;
			kfree_skb(skb1);
			skb1 = skb2;
		}
		elt++;
		*trailer = skb1;
		skb_p = &skb1->next;
	}

	return elt;
}
EXPORT_SYMBOL_GPL(skb_cow_data);

static void sock_rmem_free(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	atomic_sub(skb->truesize, &sk->sk_rmem_alloc);
}

/*
 * Note: We dont mem charge error packets (no sk_forward_alloc changes)
 */
int sock_queue_err_skb(struct sock *sk, struct sk_buff *skb)
{
	if (atomic_read(&sk->sk_rmem_alloc) + skb->truesize >=
	    (unsigned)sk->sk_rcvbuf)
		return -ENOMEM;

	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_rmem_free;
	atomic_add(skb->truesize, &sk->sk_rmem_alloc);

	skb_queue_tail(&sk->sk_error_queue, skb);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, skb->len);
	return 0;
}
EXPORT_SYMBOL(sock_queue_err_skb);

void skb_tstamp_tx(struct sk_buff *orig_skb,
		struct skb_shared_hwtstamps *hwtstamps)
{
	struct sock *sk = orig_skb->sk;
	struct sock_exterr_skb *serr;
	struct sk_buff *skb;
	int err;

	if (!sk)
		return;

	skb = skb_clone(orig_skb, GFP_ATOMIC);
	if (!skb)
		return;

	if (hwtstamps) {
		*skb_hwtstamps(skb) =
			*hwtstamps;
	} else {
		/*
		 * no hardware time stamps available,
		 * so keep the skb_shared_tx and only
		 * store software time stamp
		 */
		skb->tstamp = ktime_get_real();
	}

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = ENOMSG;
	serr->ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;

	err = sock_queue_err_skb(sk, skb);

	if (err)
		kfree_skb(skb);
}
EXPORT_SYMBOL_GPL(skb_tstamp_tx);


/**
 * skb_partial_csum_set - set up and verify partial csum values for packet
 * @skb: the skb to set
 * @start: the number of bytes after skb->data to start checksumming.
 * @off: the offset from start to place the checksum.
 *
 * For untrusted partially-checksummed packets, we need to make sure the values
 * for skb->csum_start and skb->csum_offset are valid so we don't oops.
 *
 * This function checks and sets those values and skb->ip_summed: if this
 * returns false you should drop the packet.
 */
bool skb_partial_csum_set(struct sk_buff *skb, u16 start, u16 off)
{
	if (unlikely(start > skb_headlen(skb)) ||
	    unlikely((int)start + off > skb_headlen(skb) - 2)) {
		if (net_ratelimit())
			printk(KERN_WARNING
			       "bad partial csum: csum=%u/%u len=%u\n",
			       start, off, skb_headlen(skb));
		return false;
	}
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = skb_headroom(skb) + start;
	skb->csum_offset = off;
	return true;
}
EXPORT_SYMBOL_GPL(skb_partial_csum_set);

void __skb_warn_lro_forwarding(const struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warning("%s: received packets cannot be forwarded"
			   " while LRO is enabled\n", skb->dev->name);
}
EXPORT_SYMBOL(__skb_warn_lro_forwarding);

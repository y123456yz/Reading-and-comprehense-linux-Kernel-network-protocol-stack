#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/icmp.h>

#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netfilter/nf_conntrack.h>
#endif
#include <net/netfilter/nf_conntrack_zones.h>
#include "mtrie.h"
#include "nf_sfc50_l_data.h"

#ifdef DEBUG//DBG_WARNING
#define DATA_DBG(x) x
#else
#define DATA_DBG(x)
#endif

#define SFC50_L_CACHE_BKT 8192
#define SFC50_L_CACHE_TIMEOUT (60 * HZ)

#define SFC50_L_FWD_BKT 8192

static unsigned long sfc50_l_cache_timeout = 60 * HZ;
static unsigned long sfc50_l_cache_retime = HZ;
static unsigned long sfc50_l_cache_renotify = 0;//3 * HZ;

/* 数据根 */
sfc50_l_data sfc_dt = {
	.lock = __SPIN_LOCK_UNLOCKED(sfc_dt.lock),
};
EXPORT_SYMBOL_GPL(sfc_dt);

/* declare */
static inline void sfc50_l_data_clean(void);

/* 大块内存分配 */
static void *nf_sfc50_l_mblk(unsigned int *item_numb, size_t item_size, int *vmalloced)
{
	void *ret;
	unsigned int nr_slots;
	size_t sz;

	*vmalloced = 0;

	nr_slots = *item_numb = roundup(*item_numb, PAGE_SIZE / item_size);
	sz = nr_slots * item_size;
	ret = (void *)__get_free_pages(GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
					get_order(sz));
	if (!ret) {
		*vmalloced = 1;
		printk(KERN_WARNING "nf_gate_mblk: falling back to vmalloc.\n");
		ret = __vmalloc(sz, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
	}

	return ret;
}

static void nf_sfc50_l_fblk(void *blk, unsigned int bli_size, int vmalloced)
{
	if (vmalloced)
		vfree(blk);
	else
		free_pages((unsigned long)blk, get_order(bli_size));
}

static int sfc50_l_op_role(kernel_msg *msg_ptr)
{
	unsigned int *is_inside = (unsigned int *)msg_ptr->value;

	sfc50_l_data_lock();
	
	sfc_dt.is_inside = *is_inside;
	sfc_dt.is_online = 0;
	sfc50_l_data_clean();

	sfc50_l_data_unlock();

	DATA_DBG(printk("SFC50_L: set role %s\n",
		sfc_dt.is_inside ? "INSIDE" : "OUTSIDE"););

	return 0;
}

static int sfc50_l_op_id(kernel_msg * msg_ptr)
{
	unsigned int *id = (unsigned int *)msg_ptr->value;

	sfc50_l_data_lock();
	
	sfc_dt.id = *id;
	sfc_dt.is_online = 0;
	sfc50_l_data_clean();

	sfc50_l_data_unlock();

	DATA_DBG(printk("SFC50_L: set id %08x\n",
		sfc_dt.id););

	return 0;
}

static int sfc50_l_op_online(kernel_msg * msg_ptr)
{
	unsigned int *is_online = (unsigned int *)msg_ptr->value;

	sfc50_l_data_lock();
	
	sfc_dt.is_online = *is_online;
	//sfc50_l_data_clean();

	sfc50_l_data_unlock();

	DATA_DBG(printk("SFC50_L: set %s\n",
		sfc_dt.is_online ? "ONLINE" : "OFFLINE"););

	return 0;
}

static int sfc50_l_op_auth(kernel_msg * msg_ptr)
{
	int *key_ptr = (int *)msg_ptr->value;

	sfc50_l_data_lock();
	
	sfc_dt.key = key_ptr[0];

	sfc50_l_data_unlock();

	DATA_DBG(printk("SFC50_L: set auth key %d\n", sfc_dt.key););

	return 0;
}

static int sfc50_l_op_gws(kernel_msg * msg_ptr)
{
	unsigned int *gws = (unsigned int *)msg_ptr->value;

	sfc50_l_data_lock();
	
	memcpy(sfc_dt.gws, gws, sizeof(unsigned int) * MAX_STATION_GATE);

	sfc50_l_data_unlock();

	DATA_DBG({
		unsigned int i;
		char buf[256];
		char buf2[32];

		strcpy(buf, "SFC50_L: set gws ");
		for(i = 0; i < MAX_STATION_GATE - 1; i ++) {
			sprintf(buf2, "%08x ", sfc_dt.gws[i]);
			strcat(buf, buf2);
		}
		sprintf(buf2, "%08x\n", sfc_dt.gws[MAX_STATION_GATE - 1]);
		strcat(buf, buf2);
	});

	return 0;
}

static inline void sfc50_l_del_one_item(sfc_ct *cache_ptr)
{
	hlist_del_init((&(cache_ptr->list)));
	hlist_del_init((&(cache_ptr->list_rule)));

	kmem_cache_free(sfc_dt.ct_cache, cache_ptr);

	DATA_DBG(printk("<%s, %d>: cache timeout: <dst:%08x, sp:%u, dp:%u, proto:%u, act:%s>\n",
		__FILE__, __LINE__, ntohl(cache_ptr->dst), ntohs(cache_ptr->sp),
		ntohs(cache_ptr->dp), cache_ptr->proto, (cache_ptr->nf_result ==NF_ACCEPT) ?
		"ACCEPT" : "DROP"););
}

static inline sfc_fwd_item *__sfc50_l_fwd_find(unsigned int hash_val, unsigned int dst)
{
	sfc_fwd_item *fwd_ptr;
	struct hlist_node *n;

	hlist_for_each_entry(fwd_ptr, n, &(sfc_dt.fwd_bkt[hash_val]),
							list) {
		if(fwd_ptr->data.dst == dst)
			return fwd_ptr;
	}

	return NULL;
}

static inline sfc_fwd_item *sfc50_l_fwd_find(unsigned int dst)
{
	unsigned int hash_val;

	hash_val = jhash_1word(dst, sfc_dt.fwd_rand) & 
		(sfc_dt.fwd_bkt_numb - 1);

	return __sfc50_l_fwd_find(hash_val, dst);
}

static inline void sfc50_l_fwd_cache_clean(struct hlist_head *head_ptr)
{
	sfc_ct *cache_ptr;
	
	while (!hlist_empty(head_ptr)) {
		cache_ptr = hlist_entry(head_ptr->first,
			sfc_ct, list_rule);
		if(del_timer(&(cache_ptr->timeout)))
			sfc50_l_del_one_item(cache_ptr);
	}
}

static int sfc50_l_op_fwd(kernel_msg *msg_ptr)
{
	sfc_fwd_item *fwd_ptr;
	sfc_fwd_data *fr_ptr = (sfc_fwd_data *)msg_ptr->value;
	unsigned int hash_val;

	if(fr_ptr->numb > MAX_STATION_GATE) {
		printk(KERN_ERR "<%s, %d>: mtrie item too big gw number !!!\n",
			__FILE__, __LINE__);
		return -1;
	}

	hash_val = jhash_1word(fr_ptr->dst, sfc_dt.fwd_rand) &
		(sfc_dt.fwd_bkt_numb - 1);

	if(OPER_ADD == msg_ptr->opera) {
		DATA_DBG({
				unsigned int i;
				char buf[1024];
				char bufff[32];

				sprintf(buf, "Fwd mtrie add item: <%08x, %u:[", 
						fr_ptr->dst, fr_ptr->numb);
				for(i = 0; i < fr_ptr->numb; i ++) {
					if(i + 1 == fr_ptr->numb) {
						sprintf(bufff, "%08x]>\n", fr_ptr->gw[i]);
						strcat(buf, bufff);
					} else {
						sprintf(bufff, "%08x, ", fr_ptr->gw[i]);
						strcat(buf, bufff);
					}
				}
				printk(buf);
			});

		fwd_ptr = kmem_cache_zalloc(sfc_dt.fwd_cache, GFP_KERNEL);
		if(NULL == fwd_ptr) {
			printk(KERN_ERR "<%s, %d>: mtrie item alloc failed !!!\n",
				__FILE__, __LINE__);
			return -1;
		}

		fwd_ptr->data = *fr_ptr;

		INIT_HLIST_HEAD(&(fwd_ptr->rule_cache));

		sfc50_l_data_lock();

		hlist_add_head(&(fwd_ptr->list), &(sfc_dt.fwd_bkt[hash_val]));

		sfc50_l_data_unlock();

		return 0;
	}


	sfc50_l_data_lock();
	
	fwd_ptr = __sfc50_l_fwd_find(hash_val, fr_ptr->dst);
	if(fwd_ptr) {
		hlist_del_init((&(fwd_ptr->list)));
		sfc50_l_fwd_cache_clean(&(fwd_ptr->rule_cache));
		kmem_cache_free(sfc_dt.fwd_cache, fwd_ptr);
		sfc50_l_data_unlock();

		DATA_DBG(printk("Fwd mtrie del item: <%08x>\n", fr_ptr->dst););
	}

	sfc50_l_data_unlock();

	return 0;
}

static void sfc50_l_cache_timeout_fn(unsigned long cache_item)
{
	sfc_ct *cache_ptr = (sfc_ct *)cache_item;

	sfc50_l_data_lock();

	sfc50_l_del_one_item(cache_ptr);

	sfc50_l_data_unlock();
}

static inline void sfc50_l_unreach_notify(struct sk_buff *old_skb,
													struct iphdr *oldiph,
													sfc_ct *cache_ptr,
													int now)
{
	/* 角色无关 */
	if(NF_DROP == cache_ptr->nf_result
	    && IPPROTO_ICMP != oldiph->protocol) {
	icmp_send(old_skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	DATA_DBG(printk("<%s, %d>: send cheat icmp unreach: <dst:%08x, src:%08x>\n",
		__FILE__, __LINE__, ntohl(oldiph->daddr), 	ntohl(oldiph->saddr)););
	}

	/* 仅内网角色 */
	if(sfc_dt.is_inside) {
		if(now) {
			sfc50_l_data_send(ntohl(oldiph->daddr));
			cache_ptr->tmsp = jiffies_64;
			DATA_DBG(printk("<%s, %d>: notify user-space unreach: <dst:%08x>, immediately\n",
				__FILE__, __LINE__, ntohl(oldiph->daddr)););
		}
		else {
		    sfc_fwd_item *fwd_ptr;

		    DATA_DBG(printk("<%s, %d>: will search fwd rule: ...\n",
				__FILE__, __LINE__););
			fwd_ptr = sfc50_l_fwd_find(ntohl(oldiph->daddr));
        	if(fwd_ptr) {
        		cache_ptr->nf_result = NF_ACCEPT;
        		/*- ECMP??? FIX ME -*/
	            cache_ptr->gw = htonl(fwd_ptr->data.gw[0]);
	            DATA_DBG(printk("<%s, %d>: fwd rule: found Rule\n",
					__FILE__, __LINE__););
        	} else {
        	    DATA_DBG(printk("<%s, %d>: fwd rule: found Nothing\n",
					__FILE__, __LINE__););
				cache_ptr->nf_result = NF_DROP;
			if(jiffies_64 >= (cache_ptr->tmsp +
				sfc50_l_cache_renotify)) {
    				/* re-find */
				sfc50_l_data_send(ntohl(oldiph->daddr));
				cache_ptr->tmsp = jiffies_64;
				DATA_DBG(printk("<%s, %d>: notify user-space unreach: <dst:%08x>, rate limit\n",
					__FILE__, __LINE__, ntohl(oldiph->daddr)););
			}
		}
	}
}
}

static inline sfc_ct *sfc50_l_cache_find(unsigned int hash_val,
												struct iphdr *oldiph,
												unsigned short source,
												unsigned short dest)
{
	sfc_ct *cache_ptr;
	struct hlist_node *n;

	hlist_for_each_entry(cache_ptr, n, &(sfc_dt.ct_bkt[hash_val]),
							list) {
		if(cache_ptr->dst == oldiph->daddr
			&& cache_ptr->sp == source
			&& cache_ptr->dp == dest
			&& cache_ptr->proto == oldiph->protocol) {
			return cache_ptr;
		}
	}

	return NULL;
}

static inline sfc_ct *sfc50_l_cache_add(unsigned int hash_val,
												struct iphdr *oldiph,
												unsigned short source,
												unsigned short dest)
{
	sfc_ct *cache_ptr;

	cache_ptr = kmem_cache_zalloc(sfc_dt.ct_cache, GFP_ATOMIC);
	if(unlikely(!cache_ptr)) {
		printk(KERN_ERR "<%s, %d>: cache, no memory !!!\n",
			__FILE__, __LINE__);
		return NULL;
	}
	cache_ptr->dst = oldiph->daddr;
	cache_ptr->sp = source;
	cache_ptr->dp = dest;
	cache_ptr->proto = oldiph->protocol;
	
	hlist_add_head(&(cache_ptr->list), &(sfc_dt.ct_bkt[hash_val]));

	return cache_ptr;
}

static inline unsigned int sfc50_l_gw_find_inside(unsigned int hash_val,
													struct sk_buff *old_skb,
													struct iphdr *oldiph,
													unsigned short source,
													unsigned short dest,
													unsigned int *newip)
{
	sfc_fwd_item *fwd_ptr;
	sfc_ct *cache_ptr;

	/* cache 查找 */
	cache_ptr = sfc50_l_cache_find(hash_val, oldiph, source, dest);
	if(likely(cache_ptr)) {
		DATA_DBG(printk("<%s, %d>: cache hit: <dst:%08x, sp:%u, dp:%u, proto:%u, act:%s>\n",
			__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
			oldiph->protocol, (cache_ptr->nf_result ==NF_ACCEPT) ? "ACCEPT" : "DROP"););

        if(NF_ACCEPT == cache_ptr->nf_result) {
    	    unsigned long newtime;
    	    
		newtime = jiffies + sfc50_l_cache_timeout;
		DATA_DBG(printk("<%s, %d>: cache hit: <dst:%08x, sp:%u, dp:%u, proto:%u, act:%s>\n",
			__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
			oldiph->protocol, (cache_ptr->nf_result ==NF_ACCEPT) ? "ACCEPT" : "DROP"););
		if(newtime - cache_ptr->timeout.expires >=
			sfc50_l_cache_retime) {
			mod_timer_pending(&(cache_ptr->timeout), newtime);
			DATA_DBG(printk("<%s, %d>: cache timer refresh\n",
				__FILE__, __LINE__););
		}
    	}
    	else {
			sfc50_l_unreach_notify(old_skb, oldiph, cache_ptr, 0);
    	}

		goto fnd_out;
	}

	/* cache 添加 */
	cache_ptr = sfc50_l_cache_add(hash_val, oldiph, source, dest);
	if(unlikely(!cache_ptr)) 
		return NF_DROP;
	fwd_ptr = sfc50_l_fwd_find(ntohl(oldiph->daddr));
	if(fwd_ptr) {
		cache_ptr->nf_result = NF_ACCEPT;
		/*- ECMP??? FIX ME -*/
		cache_ptr->gw = htonl(fwd_ptr->data.gw[0]);
		hlist_add_head(&(cache_ptr->list_rule), &(fwd_ptr->rule_cache));
		DATA_DBG({
			unsigned int i;
			char buf[1024];
			char bufff[32];

			sprintf(buf, "<%s, %d>: Fwd find: <%08x, %u:[", 
				__FILE__, __LINE__,	fwd_ptr->data.dst,
				fwd_ptr->data.numb);
			for(i = 0; i < fwd_ptr->data.numb; i ++) {
				if(i + 1 == fwd_ptr->data.numb) {
					sprintf(bufff, "%08x]>\n", fwd_ptr->data.gw[i]);
					strcat(buf, bufff);
				} else {
					sprintf(bufff, "%08x, ", fwd_ptr->data.gw[i]);
					strcat(buf, bufff);
				}
			}
			printk(buf);
		});
		DATA_DBG(printk("<%s, %d>: cache add <dst:%08x, sp:%u, dp:%u, proto:%u, act:ACCEPT>\n",
			__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
			oldiph->protocol););
	}
	else {
		cache_ptr->nf_result = NF_DROP;
		hlist_add_head(&(cache_ptr->list_rule), &(sfc_dt.ct_drop_list));
		sfc50_l_unreach_notify(old_skb, oldiph, cache_ptr, 1);
		DATA_DBG(printk("<%s, %d>: cache add <dst:%08x, sp:%u, dp:%u, proto:%u, act:DROP>\n",
			__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
			oldiph->protocol););
	}
	setup_timer(&(cache_ptr->timeout), sfc50_l_cache_timeout_fn,
		(unsigned long)cache_ptr);
	cache_ptr->timeout.expires = jiffies + sfc50_l_cache_timeout;
	add_timer(&(cache_ptr->timeout));

fnd_out:
	*newip = cache_ptr->gw;

	return cache_ptr->nf_result;
}

static inline unsigned int sfc50_l_gw_find_outside(unsigned int hash_val,
															struct sk_buff * old_skb,
															struct iphdr * oldiph,
															unsigned short source,
															unsigned short dest,
															unsigned int * newip)
{
	sfc_ct *cache_ptr;
	unsigned long newtime;

	/* cache 查找 */
	cache_ptr = sfc50_l_cache_find(hash_val, oldiph, source, dest);
	if(likely(cache_ptr)) {
		newtime = jiffies + sfc50_l_cache_timeout;
		DATA_DBG(printk("<%s, %d>: cache hit: <dst:%08x, sp:%u, dp:%u, proto:%u, act:%s>\n",
			__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
			oldiph->protocol, (cache_ptr->nf_result == NF_ACCEPT) ? "ACCEPT" : "DROP"););
		if(newtime - cache_ptr->timeout.expires >=
			sfc50_l_cache_retime) {
			mod_timer_pending(&(cache_ptr->timeout), newtime);
			DATA_DBG(printk("<%s, %d>: cache timer refresh\n",
				__FILE__, __LINE__););
		}

		/* 不可达通告 */
		if(NF_DROP == cache_ptr->nf_result) 
			sfc50_l_unreach_notify(old_skb, oldiph, cache_ptr, 0);

		goto fnd_out;
	}

	/* cache 添加 */
	cache_ptr = sfc50_l_cache_add(hash_val, oldiph, source, dest);
	if(unlikely(!cache_ptr))
		return NF_DROP;
	/*- ECMP??? FIX ME -*/
	cache_ptr->gw = htonl(sfc_dt.gws[0]);
	cache_ptr->nf_result = NF_ACCEPT; /* 对于外网角色，默认都是ACCEPT */
	setup_timer(&(cache_ptr->timeout), sfc50_l_cache_timeout_fn,
		(unsigned long)cache_ptr);
	cache_ptr->timeout.expires = jiffies + sfc50_l_cache_timeout;
	add_timer(&(cache_ptr->timeout));
	DATA_DBG(printk("<%s, %d>: cache add <dst:%08x, sp:%u, dp:%u, proto:%u, act:ACCEPT>\n",
		__FILE__, __LINE__, ntohl(oldiph->daddr), ntohs(source), ntohs(dest),
		oldiph->protocol););

fnd_out:
	*newip = cache_ptr->gw;

	return cache_ptr->nf_result;
}

unsigned int sfc50_l_gw_find(struct sk_buff *old_skb,
								struct iphdr *oldiph,
								unsigned int *newip)
{
	unsigned int hash_val;
	sfc_ct_key key;
	struct udphdr *udph;
	struct tcphdr *tcph;
	struct icmphdr *icmph;

	if(IPPROTO_UDP == oldiph->protocol) {
		udph = (struct udphdr *)((unsigned char *)oldiph +
			(oldiph->ihl << 2));
		key.sp = udph->source;
		key.dp = udph->dest;
	}
	else if(IPPROTO_TCP == oldiph->protocol) {
		tcph = (struct tcphdr *)((unsigned char *)oldiph +
			(oldiph->ihl << 2));
		key.sp = tcph->source;
		key.dp = tcph->dest;
	}
	else if(IPPROTO_ICMP == oldiph->protocol) {
		icmph = (struct icmphdr *)((unsigned char *)oldiph +
			(oldiph->ihl << 2));
		key.sp = icmph->type;
		key.dp = icmph->code;
	}
	else
		return NF_DROP;

	key.dst = oldiph->daddr;
	key.proto = oldiph->protocol;
	hash_val = jhash(&key, sizeof(key), sfc_dt.ct_rand) &
		(sfc_dt.ct_bkt_numb - 1);
	
	if(sfc_dt.is_inside)
		return sfc50_l_gw_find_inside(hash_val, old_skb,
										oldiph, key.sp,
										key.dp, newip);

	return sfc50_l_gw_find_outside(hash_val, old_skb, oldiph,
										key.sp, key.dp,
										newip);
	
}
EXPORT_SYMBOL_GPL(sfc50_l_gw_find);

int sfc50_l_cache_feedback(struct iphdr *iph)
{
	sfc_ct *cache_ptr;
	unsigned int hash_val;
	sfc_ct_key key;
	
	struct l4_hdr {
		__be16	source;
		__be16	dest;
	} *chdr;

	if(unlikely(iph->protocol != IPPROTO_UDP
		&& iph->protocol != IPPROTO_TCP))
		return -1;

	chdr = (struct l4_hdr *)((unsigned char *)iph +
		(iph->ihl << 2));
	key.dst = iph->daddr;
	key.sp = chdr->source;
	key.dp = chdr->dest;
	key.proto = iph->protocol;
	hash_val = jhash(&key, sizeof(key), sfc_dt.ct_rand) &
		(sfc_dt.ct_bkt_numb - 1);

	/* cache 查找 */
	cache_ptr = sfc50_l_cache_find(hash_val, iph, chdr->source,
		chdr->dest);

	/* cache行为更新 */
	if(likely(cache_ptr)) {
		if(NF_DROP != cache_ptr->nf_result) {
			cache_ptr->nf_result = NF_DROP;
			hlist_del_init(&(cache_ptr->list_rule));
			hlist_add_head(&(cache_ptr->list_rule), &(sfc_dt.ct_drop_list));
			DATA_DBG(printk(KERN_DEBUG "<%s, %d>: ERP cause  to DROP: <dst:%08x, sp:%u, "
				"dp:%u, proto:%u>\n", __FILE__, __LINE__, ntohl(cache_ptr->dst),
				ntohs(cache_ptr->sp), ntohs(cache_ptr->dp), cache_ptr->proto););
			return 0;
		}
	}

	return -1;
}
EXPORT_SYMBOL_GPL(sfc50_l_cache_feedback);

static int sfc50_l_op_wc(kernel_msg *msg_ptr)
{
	unsigned int *mode = (unsigned int *)msg_ptr->value;

    if(OPER_ADD == msg_ptr->opera) {
	    sfc_dt.mode |= 1 << (*mode);
	}
	else {
	    sfc_dt.mode &= ~(1 << (*mode));
	}
	
	return 0;
}

static int sfc50_l_op_net(kernel_msg *msg_ptr)
{
	sfc_net *data = (sfc_net *)msg_ptr->value;

	sfc_dt.prefix = data->prefix & data->mask;
	sfc_dt.mask = data->mask;

	return 0;
}

static int sfc50_l_op_wd(kernel_msg *msg_ptr)
{
	mtrie_leaf_t *leaf_ptr;
	w_rule *fr_ptr = (w_rule *)msg_ptr->value;

	if(OPER_ADD == msg_ptr->opera) {
		leaf_ptr = kmem_cache_zalloc(sfc_dt.w_leaf_cache,
			GFP_ATOMIC);
		if(NULL == leaf_ptr) {
			printk(KERN_ERR "<%s, %d>: mtrie item alloc failed !!!\n",
				__FILE__, __LINE__);
			return -1;
		}
		leaf_ptr->prefix = fr_ptr->prefix;
		leaf_ptr->mask = fr_ptr->mask;

		sfc50_l_data_lock();
		
		if(FALSE == mtrie_leaf_insert(sfc_dt.w_root, leaf_ptr)) {
			sfc50_l_data_unlock();
			kmem_cache_free(sfc_dt.w_leaf_cache, leaf_ptr);
			printk(KERN_ERR "<%s, %d>: mtrie item add failed !!!\n",
				__FILE__, __LINE__);
			return -1;
		}

		sfc50_l_data_unlock();

		DATA_DBG(printk("<%s, %d>: w add: <%08x, %08x>\n",
			__FILE__, __LINE__, fr_ptr->prefix, fr_ptr->mask););
		
		return 0;
	}

	sfc50_l_data_lock();
	
	leaf_ptr = mtrie_lookup_exact(sfc_dt.w_root, fr_ptr->prefix, fr_ptr->mask);
	if(NULL == leaf_ptr) {
		sfc50_l_data_unlock();
		
		printk(KERN_ERR "<%s, %d>: mtrie item del failed !!!\n",
			__FILE__, __LINE__);
		return -1;
	}
	mtrie_leaf_delete(sfc_dt.w_root, leaf_ptr);

	sfc50_l_data_unlock();

	DATA_DBG(printk("<%s, %d>: w del: <%08x, %08x>\n",
		__FILE__, __LINE__, fr_ptr->prefix, fr_ptr->mask););

	kmem_cache_free(sfc_dt.w_leaf_cache, leaf_ptr);
	
	return 0;
}


/* NETLINK 接收函数 */

/* --------------- */
static void sfc50_l_data_from_user(kernel_msg *msg_ptr)
{
	if(WK_MSG_SFC50_L == msg_ptr->type) {
		if(SFC50_L_ROLE == msg_ptr->sub_type) 
			sfc50_l_op_role(msg_ptr);

		else if(SFC50_L_ID == msg_ptr->sub_type)
			sfc50_l_op_id(msg_ptr);

		else if(SFC50_L_ONLINE == msg_ptr->sub_type)
			sfc50_l_op_online(msg_ptr);

		else if(SFC50_L_AUTH == msg_ptr->sub_type)
			sfc50_l_op_auth(msg_ptr);

		else if(SFC50_L_GW == msg_ptr->sub_type)
			sfc50_l_op_gws(msg_ptr);

		else if(SFC50_L_FWD == msg_ptr->sub_type)
			sfc50_l_op_fwd(msg_ptr);

		else if(SFC50_L_WC == msg_ptr->sub_type)
			sfc50_l_op_wc(msg_ptr);

		else if(SFC50_L_WD == msg_ptr->sub_type)
			sfc50_l_op_wd(msg_ptr);

		else if(SFC50_L_NET == msg_ptr->sub_type)
			sfc50_l_op_net(msg_ptr);

		/* more ... */
		else {
			printk(KERN_ERR "<%s, %d>: netlink: bad msg sub_type !!!\n",
				__FILE__, __LINE__);
		}
	} 

	/* more ... */

	else {
		printk(KERN_ERR "<%s, %d>: netlink: bad msg type !!!\n",
			__FILE__, __LINE__);
	}
}

static void sfc50_l_data_rcv_skb(struct sk_buff *skb)
{
	kernel_msg *msg_ptr;
	struct nlmsghdr *nlh;

	nlh = nlmsg_hdr(skb);

	if (skb->len < NLMSG_SPACE(0) || skb->len < nlh->nlmsg_len ||
		nlh->nlmsg_len < NLMSG_LENGTH(sizeof(kernel_msg))) {
		printk(KERN_ERR "<%s, %s, %d>: work module: bad work_msg!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		return;
	}
	
	msg_ptr = NLMSG_DATA(nlh);

	sfc50_l_data_from_user(msg_ptr);
}

void sfc50_l_data_send(unsigned int dst)
{
	unsigned int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	unsigned int *dst_ptr;

	size = NLMSG_SPACE(sizeof(dst));
	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "<%s, %d>: netlink: skb alloc failed !!!\n",
			__FILE__, __LINE__);
		return;
	}

	nlh = NLMSG_PUT(skb, 0, 0, 0, sizeof(dst));
	nlh->nlmsg_pid = 0; /*from kernel */
	dst_ptr = NLMSG_DATA(nlh);
	*dst_ptr = dst;

	netlink_broadcast(sfc_dt.nl[1], skb, 0, 1, GFP_ATOMIC);

	return;

nlmsg_failure:
	kfree_skb(skb);
	printk(KERN_ERR "<%s, %d>: netlink: build header error !!!\n",
		__FILE__, __LINE__);
}
EXPORT_SYMBOL_GPL(sfc50_l_data_send);

#ifdef CONFIG_PROC_FS
static void *cmn_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? NULL : SEQ_START_TOKEN;
}

static void cmn_seq_stop(struct seq_file *seq, void *v)
{
}

static void *cmn_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static void sfc50_l_w_mtrie_callback(mtrie_leaf_t *leaf_entry, void *p1, void *p2)
{
	struct seq_file *seq = p1;
	char buf[128];

	sprintf(buf, "<%08x, %08x>\n", leaf_entry->prefix,
			leaf_entry->mask);
	seq_puts(seq, buf);
}

static void sfc50_l_proc_all_show(struct seq_file *seq)
{
	char buf[256];
	unsigned int i, j;
	sfc_fwd_item *fwd_ptr;
	sfc_ct *entry_ptr;
	struct hlist_node *n;
	char *mode_name[] = {
		"All",
		"Net",
		"ID",
		"White",
		"White2",
		NULL,
	};

	sfc50_l_data_lock();

	/* status */
	sprintf(buf, "Status:: Role:%s, ID:%08x, Online:%s\n\n",
		sfc_dt.is_inside ? "Inside" : "Outside",
		sfc_dt.id,
		sfc_dt.is_online ? "Yes" : "No");
	seq_puts(seq, buf);

	sprintf(buf, "Auth key: %d\n\n", sfc_dt.key);
	seq_puts(seq, buf);

	sprintf(buf, "Gws: total %u: ", sfc_dt.gw_numb);
	seq_puts(seq, buf);
	for(i = 0; i < MAX_STATION_GATE - 1; i ++) {
		sprintf(buf, "%08x ", sfc_dt.gws[i]);
		seq_puts(seq, buf);
	}
	sprintf(buf, "%08x\n\n", sfc_dt.gws[MAX_STATION_GATE - 1]);
	seq_puts(seq, buf);

	seq_puts(seq, "Fwd item: <dest, number:[gw-ip, ...]>\n");
	for(i = 0; i < sfc_dt.fwd_bkt_numb; i ++) {
		hlist_for_each_entry(fwd_ptr, n, &(sfc_dt.fwd_bkt[i]),
			list) {
			sprintf(buf, "<%08x, %u:[", fwd_ptr->data.dst,
				fwd_ptr->data.numb);
			seq_puts(seq, buf);
			for(j = 0; j < fwd_ptr->data.numb; j ++) {
				if(j + 1 == fwd_ptr->data.numb) {
					sprintf(buf, "%08x]>\n", fwd_ptr->data.gw[j]);
					seq_puts(seq, buf);
				}
				else {
					sprintf(buf, "%08x, ", fwd_ptr->data.gw[j]);
					seq_puts(seq, buf);
				}
			}
		}
	}
	seq_puts(seq, "\n");

	seq_puts(seq, "Cache item: <dst, sp, dp, proto, timestamp>\n");
	for(i = 0; i < sfc_dt.ct_bkt_numb; i ++) {
		hlist_for_each_entry(entry_ptr, n, &(sfc_dt.ct_bkt[i]),
			list) {
			sprintf(buf, "<%08x, %u, %u, %u, %llu>\n", 
				ntohl(entry_ptr->dst), ntohs(entry_ptr->sp),
				ntohs(entry_ptr->dp), entry_ptr->proto,
				entry_ptr->tmsp);
			seq_puts(seq, buf);
		}
	}
	seq_puts(seq, "\n");

    sprintf(buf, "Work model (by value): %u\n", sfc_dt.mode);
	seq_puts(seq, buf);
    for(i = 0; i < SFC50_L_M_MAX; i ++ ) {
        if(sfc_dt.mode & (1 << i)) {
        	sprintf(buf, "Work model: %s\n", mode_name[i]);
			seq_puts(seq, buf);
    	}
	}
	sprintf(buf, "Net: %08x/%08x\n", sfc_dt.prefix, sfc_dt.mask);
	seq_puts(seq, buf);
	seq_puts(seq, "White item: <dst-prefix, dst-mask>\n");
	mtrie_walk(sfc_dt.w_root, sfc50_l_w_mtrie_callback,
		seq, NULL);
	seq_puts(seq, "\n");

	sfc50_l_data_unlock();
}

static int sfc50_l_all_seq_show(struct seq_file *seq, void *v)
{
	sfc50_l_proc_all_show(seq);

	return 0;
}

static const struct seq_operations sfc50_l_all_seq_ops = {
	.start  = cmn_seq_start,
	.next   = cmn_seq_next,
	.stop   = cmn_seq_stop,
	.show   = sfc50_l_all_seq_show,
};

static int sfc50_l_all_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &sfc50_l_all_seq_ops, sizeof(struct seq_net_private));
}

static const struct file_operations sfc50_l_all_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= sfc50_l_all_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
};

static int sfc50_l_proc_init(void)
{
	if (!proc_net_fops_create(&init_net, "sfc50_l_all", 0, &sfc50_l_all_seq_fops)) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when proc_net_fops_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		return -1;
	}
	
	return 0;
}

static void sfc50_l_proc_uninit(void)
{
	proc_net_remove(&init_net, "sfc50_l_all");
}
#endif

static int sfc50_l_data_init(void)
{
	unsigned int i;
	
	sfc_dt.gws = kzalloc(sizeof(unsigned int) * MAX_STATION_GATE, GFP_KERNEL);
	if(NULL == sfc_dt.gws) {
		printk(KERN_ERR "<%s, %d>: not enough memory !!!\n",
			__FILE__, __LINE__);
		goto err_quit0;
	}

	sfc_dt.fwd_bkt_numb = SFC50_L_FWD_BKT;
	sfc_dt.fwd_bkt = nf_sfc50_l_mblk(&(sfc_dt.fwd_bkt_numb),
		sizeof(struct hlist_head), &(sfc_dt.fwd_bkt_vmed));
	if(NULL == sfc_dt.fwd_bkt) {
		panic("<%s, %s, %d>: init failed(when kzalloc)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit1;
	}
	for(i = 0; i < sfc_dt.fwd_bkt_numb; i ++) {
		INIT_HLIST_HEAD(&(sfc_dt.fwd_bkt[i]));
	}
	sfc_dt.fwd_cache = kmem_cache_create("fwd_item",
		sizeof(sfc_fwd_item), 0, SLAB_PANIC, NULL);
	if(NULL == sfc_dt.fwd_cache) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when kmem_cache_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit2;
	}

	sfc_dt.ct_bkt_numb = SFC50_L_CACHE_BKT;
	sfc_dt.ct_bkt = nf_sfc50_l_mblk(&(sfc_dt.ct_bkt_numb),
		sizeof(struct hlist_head), &(sfc_dt.ct_bkt_vmed));
	if(NULL == sfc_dt.ct_bkt) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when kmem_cache_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit3;
	}
	for(i = 0; i < sfc_dt.ct_bkt_numb; i ++) {
		INIT_HLIST_HEAD(&(sfc_dt.ct_bkt[i]));
	}
	sfc_dt.ct_cache = kmem_cache_create("ct_item",
		sizeof(sfc_ct), 0, SLAB_PANIC, NULL);
	if(NULL == sfc_dt.ct_cache) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when kmem_cache_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit4;
	}
	get_random_bytes(&(sfc_dt.ct_rand), sizeof(sfc_dt.ct_rand));
	INIT_HLIST_HEAD(&(sfc_dt.ct_drop_list));

	sfc_dt.w_root = kzalloc(sizeof(mtrie_root_t), GFP_KERNEL);
	if(NULL == sfc_dt.w_root) {
		panic("<%s, %s, %d>: init failed(when kzalloc)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit5;
	}

	sfc_dt.w_leaf_cache = kmem_cache_create("w_leaf",
		sizeof(fwd_rule_entry), 0, SLAB_PANIC, NULL);
	if(NULL == sfc_dt.w_leaf_cache) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when kmem_cache_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit6;
	}

	sfc_dt.w_node_cache = kmem_cache_create("w_node",
		sizeof(mtrie_node_t), 0, SLAB_PANIC, NULL);
	if(NULL == sfc_dt.w_node_cache) {
		printk(KERN_ERR "<%s, %s, %d>: work module: init failed(when kmem_cache_create)!!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit7;
	}

	mtrie_init(sfc_dt.w_root, sfc_dt.w_node_cache);

	printk(KERN_INFO "fwd<%u, %u>, ct<%u, %u>\n",
		SFC50_L_FWD_BKT, sfc_dt.fwd_bkt_numb, SFC50_L_CACHE_BKT,
		sfc_dt.ct_bkt_numb);
	

	return 0;

err_quit7:
	kmem_cache_destroy(sfc_dt.w_leaf_cache);
err_quit6:
	kfree(sfc_dt.w_root);
err_quit5:
	kmem_cache_destroy(sfc_dt.ct_cache);
err_quit4:
	nf_sfc50_l_fblk(sfc_dt.ct_bkt, sizeof(struct hlist_head) *
		sfc_dt.ct_bkt_numb, sfc_dt.ct_bkt_vmed);
err_quit3:
	kmem_cache_destroy(sfc_dt.fwd_cache);
err_quit2:
	nf_sfc50_l_fblk(sfc_dt.fwd_bkt, sizeof(struct hlist_head) *
		sfc_dt.fwd_bkt_numb, sfc_dt.fwd_bkt_vmed);
err_quit1:
	kfree(sfc_dt.gws);
err_quit0:
	return -1;
}

static inline void sfc50_l_data_clean(void)
{
	sfc_fwd_item *fwd_ptr;
	unsigned int i;

	for(i = 0; i < sfc_dt.fwd_bkt_numb; i ++) {
		while (!hlist_empty(&(sfc_dt.fwd_bkt[i]))) {
			fwd_ptr = hlist_entry(sfc_dt.fwd_bkt[i].first,
				sfc_fwd_item, list);
			hlist_del_init(&(fwd_ptr->list));
			sfc50_l_fwd_cache_clean(&(fwd_ptr->rule_cache));
			kmem_cache_free(sfc_dt.fwd_cache, fwd_ptr);
		}
	}

	sfc50_l_fwd_cache_clean(&(sfc_dt.ct_drop_list));

	sfc_dt.key = 0;
}

static void sfc50_l_data_uninit(void)
{
	sfc50_l_data_clean();
	kfree(sfc_dt.gws);
	nf_sfc50_l_fblk(sfc_dt.fwd_bkt, sizeof(struct hlist_head) *
		sfc_dt.fwd_bkt_numb, sfc_dt.fwd_bkt_vmed);
	kmem_cache_destroy(sfc_dt.fwd_cache);
	nf_sfc50_l_fblk(sfc_dt.ct_bkt, sizeof(struct hlist_head) *
		sfc_dt.ct_bkt_numb, sfc_dt.ct_bkt_vmed);

	mtrie_clear2(sfc_dt.w_root, (mtrie_leaf_free_func *)kmem_cache_free,
		sfc_dt.w_leaf_cache);
	kfree(sfc_dt.w_root);
	kmem_cache_destroy(sfc_dt.w_leaf_cache);
	kmem_cache_destroy(sfc_dt.w_node_cache);
}

static int __init nf_sfc50_l_data_init(void)
{	
	if(0 != sfc50_l_data_init())
		goto err_quit0;

#ifdef CONFIG_PROC_FS
	if(0 != sfc50_l_proc_init())
		goto err_quit1;
#endif

	sfc_dt.nl[0] = netlink_kernel_create(&init_net, NETLINK_KERNEL_MSG, 32,
			sfc50_l_data_rcv_skb, NULL, THIS_MODULE);
	if (sfc_dt.nl[0] == NULL) {
		printk(KERN_ERR "<%s, %s, %d>: error !!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit2;
	}

	sfc_dt.nl[1] = netlink_kernel_create(&init_net, NETLINK_KERNEL_MSG + 1, 32,
			sfc50_l_data_rcv_skb, NULL, THIS_MODULE);
	if (sfc_dt.nl[1] == NULL) {
		printk(KERN_ERR "<%s, %s, %d>: error !!!\n",
			__FILE__, __FUNCTION__, __LINE__);
		goto err_quit3;
	}

	sfc_dt.md5.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (!(sfc_dt.md5.tfm) || IS_ERR(sfc_dt.md5.tfm)) {
		printk(KERN_DEBUG "<%s, %d>: sfc50_l: MD5 init failed !!!\n",
			__FILE__, __LINE__);
		goto err_quit4;
	}

	printk(KERN_INFO "sfc50_l data module: Init OK\n");

	return 0;
err_quit4:
	netlink_kernel_release(sfc_dt.nl[1]);
err_quit3:
	netlink_kernel_release(sfc_dt.nl[0]);
err_quit2:
#ifdef CONFIG_PROC_FS
	sfc50_l_proc_uninit();
err_quit1:
#endif
	sfc50_l_data_uninit();
err_quit0:
	return -1;
}

static void __exit nf_sfc50_l_data_fini(void)
{
	crypto_free_hash(sfc_dt.md5.tfm);
	netlink_kernel_release(sfc_dt.nl[1]);
	netlink_kernel_release(sfc_dt.nl[0]);
	
#ifdef CONFIG_PROC_FS
	sfc50_l_proc_uninit();
#endif

	sfc50_l_data_uninit();
	
	printk(KERN_INFO "sfc50_l data module: UnInit OK\n");
}

module_init(nf_sfc50_l_data_init);
module_exit(nf_sfc50_l_data_fini);

MODULE_LICENSE("GPL");


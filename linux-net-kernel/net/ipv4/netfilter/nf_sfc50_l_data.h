#ifndef __NF_SFC50_L_DATA__
#define __NF_SFC50_L_DATA__

#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/list.h>
#include <linux/crypto.h>
#include "../../apps/include/private/kernel/kernel_msg.h"
#include "decode.h"
#include "mtrie.h"
#include "nf_gate_data.h"

/* conntrack */
typedef struct {
	unsigned int dst;
	unsigned short sp;
	unsigned short dp;
	unsigned char proto;
} __attribute__((packed)) sfc_ct_key;

typedef struct {
	struct hlist_node list;
	struct hlist_node list_rule;
	unsigned int dst;
	unsigned short sp;
	unsigned short dp;
	unsigned char proto;
	unsigned char pad[3];
	unsigned int gw;
	unsigned int nf_result;
	struct timer_list timeout; /* 会话删除超时 */
	u64 tmsp; /* 不可达反馈时间戳 */
} sfc_ct;

typedef struct {
	struct hlist_node list;
	struct hlist_head rule_cache;
	sfc_fwd_data data;
} sfc_fwd_item;

/* 全局数据 */
typedef struct {
	unsigned int is_inside;
	unsigned int id;
	unsigned int is_online;
	
	int key;
	unsigned int gw_numb;
	unsigned int *gws;

	struct hlist_head *fwd_bkt;
	struct kmem_cache *fwd_cache;
	int fwd_bkt_vmed;
	unsigned int fwd_bkt_numb;
	unsigned int fwd_rand;
	
	struct hlist_head *ct_bkt;
	struct hlist_head ct_drop_list;
	struct kmem_cache *ct_cache;
	int ct_bkt_vmed;
	unsigned int ct_bkt_numb;
	unsigned int ct_rand;

	unsigned int mode; /* 工作模式 */
	unsigned int prefix; /* 子网 */
	unsigned int mask;
	mtrie_root_t *w_root; /* 白名单 */
	struct kmem_cache *w_leaf_cache;
	struct kmem_cache *w_node_cache;

	struct hash_desc md5;

	spinlock_t lock;

	struct sock *nl[2];
} sfc50_l_data;

extern sfc50_l_data sfc_dt;

static inline void sfc50_l_data_lock(void)
{
	spin_lock_bh(&(sfc_dt.lock));
}

static inline void sfc50_l_data_unlock(void)
{
	spin_unlock_bh(&(sfc_dt.lock));
}

extern void sfc50_l_data_send(unsigned int dst);

extern unsigned int sfc50_l_gw_find(struct sk_buff *old_skb,
											struct iphdr *oldiph,
											unsigned int *newip);

extern int sfc50_l_cache_feedback(struct iphdr *iph);

#endif /* __NF_SFC50_L_DATA__ */

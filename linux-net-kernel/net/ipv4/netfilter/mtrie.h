/* $Id: mtrie.h,v 1.13 2010-01-26 10:00:55 zhouzhiyuan Exp $
 * $Source: /project/rmi/target/include/mtrie.h,v $
 *------------------------------------------------------------------
 * mtrie.h
 *
 * Aug 1995, Darren Kerr
 *
 * IP prefix lookup structures for m-way radix trie.
 *
 * Copyright (c) 1995-1996 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 * $Log: not supported by cvs2svn $
 * Revision 1.12  2010/01/14 09:20:19  chenshijian
 * 调整头文件
 *
 * Revision 1.11  2010/01/14 07:00:35  chenshijian
 * compile problem
 *
 * Revision 1.10  2010/01/14 03:30:28  qinjun
 * *** empty log message ***
 *
 * Revision 1.9  2010/01/14 02:44:05  qinjun
 * 编译
 *
 * Revision 1.8  2010/01/13 08:51:15  zhouzhiyuan
 * *** empty log message ***
 *
 * Revision 1.7  2010/01/13 07:20:56  lichunjiang
 * no message
 *
 * Revision 1.6  2010/01/12 02:01:19  zhengjiangyong
 * mtrie的mask和prefix必须为合法值，否则挂起。
 *
 * Revision 1.5  2010/01/11 02:48:56  zhengjiangyong
 * mtrie添加释放叶函数
 *
 * Revision 1.4  2010/01/09 06:19:48  zhouzhiyuan
 * *** empty log message ***
 *
 * Revision 1.3  2010/01/09 03:46:28  zhengjiangyong
 * 内存管理，ipv4底层接口 添加
 *
 * Revision 1.2  2010/01/08 06:58:44  zhouzhiyuan
 * 增加<netinet/in.h>引用
 *
 * Revision 1.1  2010/01/08 02:45:07  zhengjiangyong
 * 初始提交
 *
 * Revision 1.1  2008/10/13 01:58:22  chenshijian
 * NRSISS-213: (R3804转发平面) 增加R3804快速转发平面代码
 *
 * Revision 3.2  1996/03/04  15:31:17  dkerr
 * CSCdi50623:  IP flow cache needs better accounting granularity
 * Better show output.  Also allow flow stats to be exported.
 *
 *
 * Revision 3.1.2.3  1996/01/08  07:53:53  tli
 * Branch: Brat_branch
 * Adding a prefix should cause resolution of routes with a next hop
 * pointing to a less specific prefix.  This insures that next hops for
 * the new prefix are correctly assigned.
 *
 * Revision 3.1.2.2  1996/01/05  15:45:26  tli
 * Branch: Brat_branch
 * Sync to V111_0_14
 *
 * Revision 3.1.2.1  1995/12/14  23:21:38  dkerr
 * CSCdi45613:  mtrie fib support
 * Branch: Brat_branch
 * M-way radix trie support routines.
 * Early drop support for unknown routes.
 *
 * Revision 3.1  1995/12/14  19:19:59  dkerr
 * mtrie placeholder
 *
 *------------------------------------------------------------------
 * $Endlog$
 */
#ifndef __MTRIE_H__
#define __MTRIE_H__

#define MNODE_BITS      8
#define MNODE_LINKS     (1 << MNODE_BITS)
#define MNODE_MASK      (MNODE_LINKS - 1)
#define IPADDR_BITS     32

#define FALSE 0
#define TRUE 1

typedef struct mtrie_node             mtrie_node_t;
typedef struct mtrie_leaf               mtrie_leaf_t;
typedef struct mtrie_root              mtrie_root_t;

typedef void mtrie_leaf_free_func(void *arg, void *ptr);

struct mtrie_leaf
{
    mtrie_leaf_t   *back;    /* next most-specific route */
    u32   prefix;
    u32   mask;
    atomic_t          refcount;
};

struct mtrie_node
{
    mtrie_node_t *children[MNODE_LINKS];
    mtrie_root_t *root;//gate_mtroot
    int        num_children;
};

struct mtrie_root
{
    mtrie_node_t node;
    void *route_defaul;/*缺省路由，指向ufib_entry_t 或ufib6_entry_t */
	void *node_cache;//指向fwd_node_cache
    void *(*malloc_rtn)(void *cache, size_t size);//mtrie_malloc
    void (*free_rtn)(void *cache, void *);//指向mtrie_free

    u32 nodes_alloced;
    u32 memory_in_use;
    u32 node_alloc_failed;
    u32 node_refcount;

    u32 leaf_invalidates;
    u32 leaf_inserts;
    u32 leaf_refcount;
};

struct _charlong_s
{
    union
    {
        u8 byte[4];
        u32 lword;
        u16 sword[2];
    } d;
};


/*
 * The RADIXMTRIE_BIT hack allows us to differentiate a pointer to a leaf
 * from a pointer to another MTRIE.  We use bit 0, since valid
 * pointers to cache entries or arrays should never be odd byte addresses.
 */
#define MTRIE_NODE_BIT 1
#define MTRIE_NODE_BIT_IS_SET(p) ((int)p & MTRIE_NODE_BIT)
#define SET_MTRIE_NODE_BIT(p) ((mtrie_node_t *)((int)p | MTRIE_NODE_BIT))
#define MASK_MTRIE_NODE_BIT(p) ((mtrie_node_t *)((int)p & ~MTRIE_NODE_BIT))

//extern SEM_ID semMtrie;

/*
 * The IP prefix cache is stored in a multiway radix trie, where each non-leaf
 * node is a 256 entry wide array of links.  With only four octets in an
 * IPv4 destination address, the trie is a maximum of 4 layers deep.
 */
 //查找dst是否在root中，这里的root一般是白名单或者黑名单
static  __inline__ mtrie_leaf_t *
mtrie_longest_match(mtrie_root_t *root, u32 dst)
{
    mtrie_node_t *node = &root->node;
    struct _charlong_s prefix;
    u8 *cp;

    cp = prefix.d.byte;
    prefix.d.lword = ntohl(dst);

    /*
     * Use successive octets in the IP address to index a pointer
     * to the next layer down until a leaf or null entry is found.
     */

    do
        node = MASK_MTRIE_NODE_BIT(node)->children[*cp++];
    while (MTRIE_NODE_BIT_IS_SET(node));

    return((mtrie_leaf_t *)node);
}

/*
 * We're using these rather than mem_lock/free for performance reasons
 * due to very high refcount usage in large routing table with overlapping
 * routes.
 */
static __inline__  void
mtrie_leaf_lock(mtrie_root_t *root, mtrie_leaf_t *leaf)
{
    root->leaf_refcount++;
    atomic_inc(&leaf->refcount);
}

/*
 * mtrie_less_specific
 *
 * Passed a leaf, return the most specific covering leaf.
 * Fortunately, we already track this.
 */
static  __inline__ mtrie_leaf_t *
mtrie_less_specific(mtrie_leaf_t *leaf)
{
    return(leaf->back);
}



/*extern void mtrie_leaf_free(mtrie_root_t *root, mtrie_leaf_t *leaf);*/
//extern void mtrie_init(mtrie_root_t *root, void *(*malloc_rtn)(size_t), void (*free_rtn)(void *));
extern void mtrie_init(mtrie_root_t *root, void *node_cache);
extern void mtrie_leaf_delete(mtrie_root_t *root, mtrie_leaf_t *leaf);
extern int mtrie_leaf_insert(mtrie_root_t *root, mtrie_leaf_t *cptr);
extern mtrie_leaf_t *mtrie_lookup_exact(mtrie_root_t *, u32, u32);
/*extern mtrie_leaf *mtrie_leaf_alloc(mtrie_root *root, int bytes);*/
extern mtrie_leaf_t *mtrie_next_leaf(mtrie_root_t *, mtrie_leaf_t *, u8 *);
extern mtrie_leaf_t *mtrie_first_leaf(mtrie_root_t *, u32, u32, u8 *);

typedef void (*mtrie_walk_routine)(mtrie_leaf_t* , void *, void *);
extern void mtrie_walk(mtrie_root_t *root , mtrie_walk_routine callback, void *p1, void *p2);

/*samples */
extern void mtrie_clear(mtrie_root_t *root);
extern void mtrie_clear2(mtrie_root_t * root, mtrie_leaf_free_func *free_func, void *arg);
extern int mtrie_add(mtrie_root_t *root, u32  prefix, u32 mask, void *context);
extern void mtrie_delete(mtrie_root_t *root, u32  prefix, u32 mask);

#endif


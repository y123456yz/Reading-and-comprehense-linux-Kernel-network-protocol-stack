#ifndef	__SIGF_HOOK_H__
#define	__SIGF_HOOK_H__


/*
	支持这些模块
*/
#define	SIGF_MOD_IP		0
#define	SIGF_MOD_TCP		1
#define	SIGF_MOD_UDP		2
#define	SIGF_MOD_GIOP		3
#define	SIGF_MOD_SHPKT	4
#define	SIGF_MOD_MAX		5

/*
	回调函数的返回值的低8位
*/
#define SIGF_DROP		0	/* 停止调用，不转发该报文 */
#define SIGF_FORWARD	1	/* 停止调用，转发该报文 */
#define SIGF_CONTINUE	2	/* 继续调用下一模块的处理函数 */

/*
	回调函数的返回值的一些标志，由高到低定义
*/
//#define	SIGF_DONT_FREE	0x80000000	/* 不要释放mbuf */

/*
	用来取回调函数的返回值的低8位
*/
#define	SIGF_GET_RS(_X)	((_X) & 0xFF)
#define	SIGF_IS_RS(_X, _V) (SIGF_GET_RS(_X) == (_V))

/*
	用于回调函数间传递参数的数据结构
*/
typedef struct sigf_info_s {
	/* 地址、端口号都是主机字节序 */
	u32	src_addr;
	u32	dst_addr;
	u8	ip_hdr_len;
	u8	proto;
	u16	reserv;
	u16	src_port;
	u16	dst_port;
	/* IP数据报文总长度 */
	u16	ip_total_len;
	/* UDP/TCP用户数据的开始偏移 */
	u16	user_data_ofs;
	/* TCP/UDP用户数据长度 */
	u16	user_data_len;
	struct sk_buff	*skb;
	void	*ext;
} sigf_info_t;

#if 0
/* 
	向某模块注册自己的回掉函数
	callback: int sigf_hook_func(sigf_info_t *si);
*/
STATUS sigf_hook_reg(int mod, FUNCPTR callback, int pri);
/* 
	开始调用注册再某模块上的回掉函数
*/
extern int sigf_hook(int mod, sigf_info_t *si);

extern STATUS sigf_hook_init_phase1(void);
extern STATUS sigf_hook_init_phase2(void);
#endif

#endif



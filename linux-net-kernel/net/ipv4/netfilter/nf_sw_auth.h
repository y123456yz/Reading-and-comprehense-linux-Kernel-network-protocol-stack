#ifndef __NF_SW_AUTH_H__
#define __NF_SW_AUTH_H__

#include <linux/list.h>


#define NF_LOCAL_TIME_UTC_SECOND		(8*60*60)//8小时 UTC时间，同北京时间差8小时

#define NF_SWITCH_HASH_TABLE_SIZE	1024

#define NF_SWITCH_TIME_VALIDE 		1//满足时间对象要求
#define NF_SWITCH_TIME_INVALIDE 	0//表示时间范围是否有效

#define NF_SWITCH_IN_TO_OUT	1
#define NF_SWITCH_OUT_TO_IN	2
#define NF_SWITCH_BIDIRECTION	3

#define NF_SWITCH_LIMIT_MD_LEN	32

/*应用协议编码表数据结构*/
#define NF_APP_ITEM_REL_TYPE_UNDEFINED 0xff
#define NF_APP_ITEM_REL_TYPE_ANY       0
#define NF_APP_ITEM_REL_TYPE_EQUAL     1
#define NF_APP_ITEM_REL_TYPE_LEEQUAL        5
#define NF_APP_ITEM_REL_TYPE_GEEQUAL        6
#define NF_APP_ITEM_REL_TYPE_IN        7
#define NF_APP_ITEM_REL_TYPE_ENUM      9

/*列表scope_list所包含的节点的端口范围数据结构如下：*/
/*如果协议号是TCP：*/
struct nf_ac_tcp_port_scope{
	unsigned char src_op;		/*源端口关系 =  <=  >=  IN  枚举，ANY   IN表示区间*/
	unsigned char src_num;		/*源端口数量*/
	unsigned char dst_op;		/*目的端口关系*/
	unsigned char dst_num;		/*目的端口数量*/
	unsigned short port[0];		/*端口数组，数组个数决定于源端口和目的端口的数量之和，
						  *排列顺序是源端口之后是目的端口
						  */
};

/*如果协议号是UDP：*/
struct nf_ac_udp_port_scope{
	unsigned char src_op;		/*源端口关系 =  <=  >=  IN  枚举，ANY*/
	unsigned char src_num;		/*源端口数量*/
	unsigned char dst_op;		/*目的端口关系*/
	unsigned char dst_num;		/*目的端口数量*/
	unsigned short port[0];		/*端口数组，数组个数决定于源端口和目的端口的数量之和，
						  *排列顺序是源端口之后是目的端口
						  */
};

/*如果协议号是ICMP：*/
struct nf_ac_icmp_scope{
	unsigned char type_op;		/*ICMP类型关系 =  <=  >=  IN  枚举，ANY*/
	unsigned char type_num;	/*源端口数量*/
	unsigned char code_op;		/*代码值的关系*/
	unsigned char code_num;	/*代码值的数量*/
	unsigned char array[0];		/*类型和代码数组，数组个数决定于类型和代码的数量
						  *排列顺序是类型数组之后是代码数组
						  */
};

typedef struct _nf_app_coding_content_scope{
	struct list_head lh;
	unsigned char proto;//yang 应用协议的子项子协议类型
	union {
		struct nf_ac_tcp_port_scope tcp;
		struct nf_ac_udp_port_scope udp;
		struct nf_ac_icmp_scope icmp;
	}content;
}nf_app_coding_content_scope;


#define NF_APP_STATUS_ON	1
#define NF_APP_STATUS_OFF	0
typedef struct _nf_app_coding{//这里面存的是一条应用协议
	struct hlist_node hlist;//通过该链表连接到gate_app_coding_kernel_hash_array中
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//应用协议索引 index 
	unsigned int h_seq;//yang 索引值sequence转换为seq  见函数_nf_gate_md5_to_hseq
	unsigned char status;/*禁用还是启用 页面上可以启用和禁用该条应用协议 */

    /*
    罗凯(罗凯) 15:42:37
                /// </summary>
                TCP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                UDP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                ICMP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                PING = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                HTT
    罗凯(罗凯) 15:42:37
    P = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                SMTP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                FTP = ApprotocolControlLevelEnum.LevelOne,
                /// <summary>
                /// 
                /// </summary>
                POP3 = ApprotocolControlLevelEnum.LevelOne
    罗凯(罗凯) 15:42:37
     /// <summary>
                /// 
                /// </summary>
                LDG = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                SDG = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                RTITP = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
                /// </summary>
                CSMXP = ApprotocolControlLevelEnum.levelThree,
                /// <summary>
                /// 
    罗凯(罗凯) 15:42:50
    one，two，three分别对应1,2,3*/
	unsigned char intensity;//对应MCP中XML里面的"CtrlLevel"
	unsigned char control_type;////长报文，短报文，实时报文等 参考_gate_show_app_control_type   实际上没什么用
	unsigned int pro_num;//子协议的个数 指的是自协议中TCP UDP和ICMP的个数  加了2个TCP 一个UDP，4个ICMP，则该值为7
	char* name;//协议名

    //            协议 	源端口/类型关系 	源端口/值 	目的端口/类型关系 	目的端口/值 
	//里面存的是   TCP	  =	                 5555 	       any	
	struct list_head app_coding_list;//存放子协议的链表，参考WEB页面  nf_app_coding_content_scope  里面包括应用协议的TCP  UDP  ICMP
}nf_app_coding;


/*===============================================================*/

#define NF_ADDR_ITEM_REL_TYPE_ANY       0
#define NF_ADDR_ITEM_REL_TYPE_EQUAL        1
#define NF_ADDR_ITEM_REL_TYPE_IN      2
#define NF_ADDR_ITEM_REL_TYPE_ENUM      3

typedef struct _nf_sw_limit_address_item{
	struct list_head lh;
	unsigned char type;//网段  区间  枚举 参考WEB
	unsigned char count;//如果是区间，并且区间里面有例外，则arry[0]和arry[1]是区间的上下限地址，后面的arry[2],arry[3]等则是例外地址
	unsigned int array[0];
}nf_sw_limit_addr_item;

//例:如果地址对象里面填的是1.2.3.3/17,12.3.3.3/17 ，则实际上web是按照发送两次发下来的，也就是_nf_sw_limit_address_item为2
//如果地址对象里面填的是枚举 1.1.1.1,2.2.2.2,3.3.3.3，则是一次发送过来的，item还是为1
//如果地址对象里面是区间1.2.3.3-1.3.3.3例外地址：1.2.3.3,1.3.3.2,1.2.5.2 ，则item为1,arry数组存的是1.2.3.3 1.3.3.3 1.2.3.3 1.3.3.2 1.2.5.2 
//如果未任意，则count为0
typedef struct _nf_sw_limit_addr{
	struct hlist_node hlist;
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//YANG  地址对象索引index
	unsigned int h_seq;//通过_nf_gate_md5_to_hseq把上面的地址对象index转换为seq
	char* name;//地址对象名
	struct list_head item_list;//_nf_sw_limit_address_item
}nf_sw_limit_addr;


#define NF_ITEM_REL_TYPE_ANY       0
#define NF_ITEM_REL_TYPE_IN        1//表示从某个时间到某个时间，时间是连续的  1日零点到12日两点
#define NF_ITEM_REL_TYPE_ENUM      2//从某一天到某一天中的几点到几点时间段是不连续的  1日到12日中的零点到两点之间

//类型为any的时候，day,start_tm,end_tm无效，当为区间的时候day无效
typedef struct _nf_sw_limit_time_item{
	struct list_head lh;
	unsigned char tm_type;//时间对象类型     任意   区间   枚举  类型为any的时候，day,start_tm,end_tm无效，当为区间的时候day无效
	unsigned char day;//星期 按照位与的关系，从低位到高危一次是 星期天 星期一 。。。。。    _nf_show_sw_limit_time_day
	unsigned int start_tm;//起始时间  时间戳           如果为区间的话，如果该值转换后的实际为start_tm:2013-12-1(日期起始时间) 14:55:0(时钟起始时间) 则日期区间其实时间，时间段其实时间 end_tm:2013-12-20 21:57:1类似
	unsigned int end_tm;
}nf_sw_limit_time_item;

typedef struct _nf_sw_limit_time{
	struct hlist_node hlist;//加到gate_sw_limit_time_kernel_hash_array  hash表中
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//索引index
	unsigned int h_seq;//索引转换后的seq值
	unsigned int effective_area;		/*作用域*/
	char* name;//时间对象名字
	struct list_head item_list;//_nf_sw_limit_time_item
	struct timer_list timer;
	unsigned int tm_flag;
}nf_sw_limit_time;

/*===============================================================*/
#define NF_SW_AUTH_SRC_TYPE_ANY		0
#define NF_SW_AUTH_SRC_TYPE_OBJ		1
#define NF_SW_AUTH_SRC_TYPE_PREFIX	2

#define NF_SW_AUTH_DST_TYPE_ANY		0
#define NF_SW_AUTH_DST_TYPE_OBJ		1
#define NF_SW_AUTH_DST_TYPE_PREFIX	2

#define NF_SW_AUTH_TIME_TYPE_ANY		0//时间对象  任意
#define NF_SW_AUTH_TIME_TYPE_OBJ		1//时间对象类型为区间或者枚举，参考WEB网页

typedef struct _nf_switch_id_prefix{
	unsigned int id;
	unsigned int id_prefix;
}nf_switch_id_prefix;

typedef struct _nf_switch_app_coding{
	struct list_head lh;
	char app_seq[NF_SWITCH_LIMIT_MD_LEN+1];//通过该值获取gate_app_coding_kernel_hash_array键值
}nf_switch_app_coding;

#define NF_SW_AUTH_AREA_ALL		0
#define NF_SW_AUTH_AREA_REGION	1
#define NF_SW_AUTH_AREA_AGENT	2


//一条交换规则只能添加一个时间对象 一个地址对象 可以多个应用协议
typedef struct _nf_switch_authority{
	struct hlist_node hlist;
	char sequence[NF_SWITCH_LIMIT_MD_LEN+1];//该规则的索引值
	unsigned int h_seq;
	unsigned char log_level;			/*日志级别  yang 实际上没什么用 */
	char* des;
	struct list_head app_coding_list;	/*应用协议编码  应用协议直接加到该链表中 nf_switch_app_coding */
	unsigned char dst_type;//添加交换规则的时候，目的地址类型:任意 地址对象  地址/地址前缀
	union{
		unsigned int obj;
		nf_switch_id_prefix prefix;
	}dst;
	char dst_seq[NF_SWITCH_LIMIT_MD_LEN+1];//通过该值作为所有，从而获取gate_sw_limit_addr_kernel_hash_array键值
	unsigned char time_type;
	char tm_obj[NF_SWITCH_LIMIT_MD_LEN+1];//时间对象索引 index      时间对象的有效性通过定时器来完成
	unsigned int tm_flag;//时间对象是否有效，只有有效该规则才有用         时间对象为任意类型的时候置1   函数中设置__gate_sw_time_validate_authority
}nf_switch_authority;


/*********************************************
	
*/
typedef struct _nf_switch_user_rule_index{//为用户分配的规则  该节点添加到_nf_switch_user_idip的rule_list
	struct list_head lh;//
	char rule_seq[NF_SWITCH_LIMIT_MD_LEN+1];
}nf_switch_user_rule_index;

typedef struct _nf_switch_user_idip{
	struct hlist_node id_hlist;
	struct hlist_node ip_hlist;
	unsigned int id;
	unsigned int ip;
	struct list_head rule_list;//nf_switch_user_rule_index
	struct list_head dynamic_rule_list;
}nf_switch_user_idip;

typedef struct _nf_switch_auth_mem_count{
	int app_coding_scp;//应用协议下面的子协议总个数
	int app_coding;//应用协议个数，在web上面添加一条的时候，这里就会加一，删除一条的时候就会减1
	int app_coding_name;
	int limit_time_item;
	int limit_time;
	int limit_time_name;
	int limit_addr_item;
	int limit_addr;
	int limit_addr_name;//地址对象计数
	int pri_des;//
	int pri;//交换规则个数,包括用户自定义规则和系统规则
	int pri_app;//应用协议被引用的次数，包括系统规则和用户自定义规则应用的
} nf_switch_auth_mem_count;

extern spinlock_t gate_privilege_lock;

static inline void lock_privilege(void)
{
	spin_lock_bh(&gate_privilege_lock);
}

static inline void unlock_privilege(void)
{
	spin_unlock_bh(&gate_privilege_lock);
}

#endif

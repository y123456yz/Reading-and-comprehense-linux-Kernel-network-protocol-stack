#ifndef __NET_SCHED_GENERIC_H
#define __NET_SCHED_GENERIC_H

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <net/gen_stats.h>
#include <net/rtnetlink.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;

// Á÷¿ØËÙÂÊ¿ØÖÆ±í½á¹¹ £¨Ò»£©¿ÕÏĞ×ÊÔ´Á÷¿ØËã·¨
struct qdisc_rate_table { //ËùÓĞµÄ¶¼Ìí¼Óµ½qdisc_rtab_list
	struct tc_ratespec rate;
	u32		data[256];//²Î¿¼Ó¦ÓÃ²ãtc_calc_rtable   //ÕâÀïµÃµ½µÄ¾ÍÊÇ2047¸ö×Ö½ÚËùÏûºÄµÄ¿ÕÏĞ×ÊÔ´¡£
	struct qdisc_rate_table *next;
	int		refcnt;
};

//qdisc->state
enum qdisc_state_t {
	__QDISC_STATE_RUNNING,//ÔÚ__qdisc_runÖĞÇå³ıÖÃÎ»¡£ __QDISC_STATE_RUNNING±êÖ¾ÓÃÓÚ±£Ö¤Ò»¸öÁ÷¿Ø¶ÔÏó²»»áÍ¬Ê±±»¶à¸öÀı³ÌÔËĞĞ¡£
	__QDISC_STATE_SCHED,
	__QDISC_STATE_DEACTIVATED,
};

struct qdisc_size_table {
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};
/*
tc¿ÉÒÔÊ¹ÓÃÒÔÏÂÃüÁî¶ÔQDisc¡¢ÀàºÍ¹ıÂËÆ÷½øĞĞ²Ù×÷£º
add£¬ÔÚÒ»¸ö½ÚµãÀï¼ÓÈëÒ»¸öQDisc¡¢Àà»òÕß¹ıÂËÆ÷¡£Ìí¼ÓÊ±£¬ĞèÒª´«µİÒ»¸ö×æÏÈ×÷Îª²ÎÊı£¬´«µİ²ÎÊıÊ±¼È¿ÉÒÔÊ¹ÓÃIDÒ²¿ÉÒÔÖ±½Ó´«µİÉè±¸µÄ¸ù¡£Èç¹ûÒª½¨Á¢Ò»¸öQDisc»òÕß¹ıÂËÆ÷£¬¿ÉÒÔÊ¹ÓÃ¾ä±ú(handle)À´ÃüÃû£»Èç¹ûÒª½¨Á¢Ò»¸öÀà£¬¿ÉÒÔÊ¹ÓÃÀàÊ¶±ğ·û(classid)À´ÃüÃû¡£
remove£¬É¾³ıÓĞÄ³¸ö¾ä±ú(handle)Ö¸¶¨µÄQDisc£¬¸ùQDisc(root)Ò²¿ÉÒÔÉ¾³ı¡£±»É¾³ıQDiscÉÏµÄËùÓĞ×ÓÀàÒÔ¼°¸½ÊôÓÚ¸÷¸öÀàµÄ¹ıÂËÆ÷¶¼»á±»×Ô¶¯É¾³ı¡£
change£¬ÒÔÌæ´úµÄ·½Ê½ĞŞ¸ÄÄ³Ğ©ÌõÄ¿¡£³ıÁË¾ä±ú(handle)ºÍ×æÏÈ²»ÄÜĞŞ¸ÄÒÔÍâ£¬changeÃüÁîµÄÓï·¨ºÍaddÃüÁîÏàÍ¬¡£»»¾ä»°Ëµ£¬changeÃüÁî²»ÄÜÒ»¶¨½ÚµãµÄÎ»ÖÃ¡£
replace£¬¶ÔÒ»¸öÏÖÓĞ½Úµã½øĞĞ½üÓÚÔ­×Ó²Ù×÷µÄÉ¾³ı£¯Ìí¼Ó¡£Èç¹û½Úµã²»´æÔÚ£¬Õâ¸öÃüÁî¾Í»á½¨Á¢½Úµã¡£
link£¬Ö»ÊÊÓÃÓÚDQisc£¬Ìæ´úÒ»¸öÏÖÓĞµÄ½Úµã¡£
tc qdisc [ add | change | replace | link ] dev DEV [ parent qdisc-id | root ] [ handle qdisc-id ] qdisc [ qdisc specific parameters ]
tc class [ add | change | replace ] dev DEV parent qdisc-id [ classid class-id ] qdisc [ qdisc specific parameters ]
tc filter [ add | change | replace ] dev DEV [ parent qdisc-id | root ] protocol protocol prio priority filtertype [ filtertype specific parameters ] flowid flow-id
tc [-s | -d ] qdisc show [ dev DEV ]
tc [-s | -d ] class show dev DEV tc filter show dev DEV

tc qdisc show dev eth0
tc class show dev eth0
*/
//tc qdisc add dev eth0 parent 22:4 handle 33ÖĞµÄ22:4ÖĞµÄ4Êµ¼ÊÉÏ¶ÔÓ¦µÄÊÇQdiscË½ÓĞÊı¾İ²¿·Ö·ÖÀàĞÅÏ¢ÖĞµÄ3,parent 22:xÖĞµÄxÊÇ´Ó1¿ªÊ¼ÅÅ£¬µ«ÊÇ¶ÔÓ¦µ½·ÖÀàÊı×éÖĞ¾ßÌåµÄÀàµÄÊ±ºò£¬ÊÇ´Ó0¿ªÊ¼ÅÅ£¬ËùÒÔÒª¼õ1£¬ÀıÈçprio²Î¿¼prio_get
//Ç°ÑÔlinuxÄÚºËÖĞÌá¹©ÁËÁ÷Á¿¿ØÖÆµÄÏà¹Ø´¦Àí¹¦ÄÜ£¬Ïà¹Ø´úÂëÔÚnet/schedÄ¿Â¼ÏÂ£»¶øÓ¦ÓÃ²ãÉÏµÄ¿ØÖÆÊÇÍ¨¹ıiproute2Èí¼ş°üÖĞµÄtcÀ´ÊµÏÖ£¬tcºÍschedµÄ¹ØÏµ¾ÍºÃÏóiptablesºÍnetfilterµÄ¹ØÏµÒ»Ñù£¬Ò»¸öÊÇÓÃ»§²ã½Ó¿Ú£¬Ò»¸öÊÇ¾ßÌåÊµÏÖ£¬¹ØÓÚtcµÄÊ¹ÓÃ·½·¨¿ÉÏê½«Linux Advanced Routing HOWTO£¬±¾ÎÄÖ÷Òª·ÖÎöÄÚºËÖĞµÄ¾ßÌåÊµÏÖ¡£
//¸Ã½á¹¹ÖĞÎÄ³ÆºôÎª:Á÷¿Ø¶ÔÏó(¶ÓÁĞ¹æ¶¨)
//Qdisc¿ª±Ù¿Õ¼äqdisc_allocºóÃæ¸úµÄÊÇpriv_sizeÊı¾İ£¬¼ûpfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(Èë¿ÚÁ÷¿Ø¶ÔÏó ) µÈÖĞµÄpriv_size£¬ Í¼ĞÎ»¯²Î¿¼TCÁ÷Á¿¿ØÖÆÊµÏÖ·ÖÎö£¨³õ²½£© 
/*
¶ÓÁĞ¹æ³Ì·ÖÎªÎŞÀà¶ÓÁĞ¹æ³ÌºÍÓĞÀà¶ÔÁË¹æ³Ì£¬ÓĞÀàµÄ¶ÓÁĞ¹æ³Ì¿ÉÒÔ´´½¨¶à¸ö×Ó¶ÓÁĞ¹æ³Ì(¿ÉÒÔÊÇ·ÖÀàµÄÒ²¿ÉÒÔÊÇÎŞÀàµÄ¶ÓÁĞ¹æ³Ì)£¬Èç¹ûÖ»´´½¨Ò»¸öÎŞÀà¶ÓÁĞ¹æ³Ì¾ÍÏàµ±ÓÚÒ»¸öÒ¶×Ó¹æ³Ì
£¬SKBÖ±½ÓÈë¶Óµ½¸Ã¶ÓÁĞ¹æ³ÌµÄskb¶ÓÁĞÖĞ¡£Èç¹ûÊÇ´´½¨Ò»¸ö·ÖÀàµÄ¶ÓÁĞ¹æ³Ì£¬ÔòµÚÒ»¸ö´´½¨µÄ¶ÓÁĞ¹æ³Ì¾ÍÊÇ¸ú£¬ÏÂÃæ¿ÉÒÔ°üÀ¨¶à¸ö×Ó¶ÓÁĞ¹æ³Ì£¬µ«ËùÒÔ·ÖÀà¶ÓÁĞ¹æ³Ì±ØĞëÓĞ¶ÔÓ¦
µÄÒ¶×ÓÎŞÀà¶ÓÁĞ¹æ³Ì£¬ÒòÎª·ÖÀà¶ÓÁĞ¹æ³ÌÀïÃæÊÇÃ»ÓĞskb¶ÓÁĞµÄ¡£
µ±Ò»¸öSKBµ½·ÖÀà¶ÓÁĞ¹æ³ÌµÄ¸úµÄÊ±ºò£¬¸ÃÑ¡Ôñ×ßÄÇÌõ×Ó¶ÓÁĞ¹æ³ÌÈë¶ÓÄØ? Õâ¾ÍÊÇ¹ıÂËÆ÷µÄ×÷ÓÃ£¬¹ıÂËÆ÷¿ÉÒÔÍ¨¹ıIP MASKµÈĞÅÏ¢À´È·¶¨×ßÄÇ¸ö×Ó¶ÓÁĞ¹æ³Ì·ÖÖ§¡£Èç¹ûÃ»ÓĞÉèÖÃ
¹ıÂËÆ÷£¬ÔòÒ»°ã¸ù¾İskb->priorityÀ´È·¶¨×ßÄÇ¸ö·ÖÖ§¡£
tc qdisc add dev eth0 root handle 1: htb ´´½¨¸ú¶ÓÁĞ¹æ³Ì (ÔÚ´´½¨¸ú·ÖÀà¹æ³ÌµÄÊ±ºò£¬Ò»°ãÄ¬ÈÏÊÇ»áÓĞ×Ô¶ÓÁĞ¹æ³ÌµÄ£¬ÀıÈçpfifoÎŞÀà¹æ³Ì)
tc class add dev eth0 parent 1: classid 1:2 htb xxxx  ÔÚ1:¶ÓÁĞ¹æ³ÌÏÂÃæµÄµÚ1:2·ÖÖ§ÉÏ£¬ÓÃhtb´´½¨Ò»¸ö×ÓÓĞÀà¶ÓÁĞ¹æ³Ìhtb¡£²¢ÇÒÔÚxxxÖĞÖ¸¶¨htbµÄ²ÎÊıĞÅÏ¢
tc class add dev eth0 parent 1: classid 1:1 htb xxxx  ÔÚ1:¶ÓÁĞ¹æ³ÌÏÂÃæµÄµÚ1:1·ÖÖ§ÉÏ£¬ÓÃhtb´´½¨Ò»¸ö×ÓÓĞÀà¶ÓÁĞ¹æ³Ìhtb¡£²¢ÇÒÔÚxxxÖĞÖ¸¶¨htbµÄ²ÎÊıĞÅÏ¢
tc filter add dev eth0 protocol ip parent 1: prio 2 u32 match ip dst 4.3.2.1/32 flowid 1:2 Èç¹ûÊÕµ½µÄÊÇipµØÖ·Îª4.3.2.1µÄSKB°ü£¬Ôò×ß×Ó¶ÓÁĞ¹æ³Ì1:2Èë¶Ó£¬¶ø²»ÊÇ×ß1:1·Ö×ÓÈë¶Ó
*/ //×îºÃµÄÔ´ÂëÀí½â²Î¿¼<<linuxÄÚºËÖĞÁ÷Á¿¿ØÖÆ>>
struct Qdisc { /* ²Î¿¼ TCÁ÷Á¿¿ØÖÆÊµÏÖ·ÖÎö£¨³õ²½£©*/ //prio_sched_dataÖĞµÄqueuesÖ¸Ïò¸ÃQdisc              #×¢ÒâÃüÁîÖĞµÄID(parent 1:2 xxx flowid 3:3)²ÎÊı¶¼±»Àí½âÎª16½øÖÆµÄÊı
//qdisc_alloc·ÖÅäÖĞÔÚstruct Qdisc½á¹¹ºóÃæµÄË½ÓĞÊı¾İÎªpfifo_qdisc_ops prio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_opsÖĞµÄpriv_size²¿·Ö
    //enqueueºÍdequeueµÄ¸³Öµ¼ûqdisc_alloc
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev); /* Èë¶Ó½Ó¿Ú */
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);  /* ³ö¶Ô½Ó¿Ú */
	unsigned		flags; //ÅÅ¶Ó¹æÔò±êÖ¾£¬È¡ÖµÎªÏÂÃæÕâ¼¸ÖÖºê¶¨Òå  TCQ_F_THROTTLED
#define TCQ_F_BUILTIN		1 //±íÊ¾ÅÅ¶Ó¹æÔòÊÇ¿ÕµÄÅÅ¶Ó¹æÔò£¬ÔÚÉ¾³ıÊÍ·ÅÊ±²»ĞèÒª×ö¹ı¶àµÄ×ÊÔ´ÊÍ·Å
#define TCQ_F_THROTTLED		2 //±êÊ¶ÅÅ¶Ó¹æÔòÕı´¦ÓÚÓÉÓÚÏŞÖÆ¶øÑÓÊ±³ö¶ÓµÄ×´Ì¬ÖĞ 
#define TCQ_F_INGRESS		4 //±íÊ¾ÅÅ¶Ó¹æÔòÎªÊäÈëÅÅ¶Ó¹æÔò
#define TCQ_F_CAN_BYPASS	8
#define TCQ_F_MQROOT		16
#define TCQ_F_WARN_NONWC	(1 << 16)// ×÷ÎªÒÑ¾­´òÓ¡ÁË¾¯¸æĞÅÏ¢µÄ±êÖ¾
    /*
    ÓÉÓÚÅÅ¶Ó¹æÔòµÄÄÚ´æĞèÒª32×Ö½Ú¶ÔÆë£¬¶øÍ¨¹ı¶¯Ì¬·ÖÅäµÃµ½µÄÄÚ´æÆğÊ¼µØÖ·²»Ò»¶¨ÊÇ32×Ö½Ú
    ¶ÔÆë£¬Òò´ËĞèÒªÍ¨¹ıÌî³ä½«¶ÓÁĞ¹æÔò¶ÔÆëµ½32×Ö½Ú´¦¡£
    */
	int			padded;

	/*pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_opsÕâ¼¸¸ö¶¼Îª³ö¿Ú£¬ingress_qdisc_opsÎªÈë¿Ú */
	struct Qdisc_ops	*ops;//prio¶ÓÁĞ¹æÔòopsÎªpfifo_qdisc_ops£¬ÆäËû»¹ÓĞprio_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops ingress_qdisc_ops(Èë¿ÚÁ÷¿Ø¶ÔÏó ) µÈ£¬ 
	struct qdisc_size_table	*stab;
	struct list_head	list;//Á¬½Óµ½ËùÅäÖÃµÄÍøÂçÉè±¸ÉÏ

	/*ÅÅ¶Ó¹æÔòÊµÀıµÄ±êÊ¶·ÖÎªÖ÷±àºÅ²¿·ÖºÍ¸±±àºÅ²¿·Ö£¬ÆäÖĞÖ÷±àºÅ²¿·ÖÓÉÓÃ»§·ÖÅä£¬·¶Î§´Ó
	0X0001µ½0X7FFFF£¬Èç¹ûÓÃ»§Ö¸¶¨Ö÷±àºÅÎª0£¬ÄÇÃ´ÄÚºË½²ÔÚ0X8000µ½0XFFFFÖ®¼ä·ÖÅäÒ»¸öÖ÷±àºÅ
	±êÊ¶ÔÚµ¥¸öÍøÂçÉè±¸ÊÇÎ¨Ò»µÄ£¬µ«ÔÚ¶à¸öÍøÂçÉè±¸Ö®¼ä¿ÉÒÔÓÉÖØ¸´*/
	u32			handle; //±¾QdiscµÄ¾ä±ú£¬tc qdisc add dev eth0 root handle 22ÖĞµÄ22
	u32			parent;//¸¸¶ÓÁĞ¹æÔòµÄ¾ä±úÖµ  tc qdisc add dev eth0 parent 22:4 handle 33 ÖĞhandleÎª33 parentÎª22
	atomic_t		refcnt;//ÒıÓÃ¼ÆÊı
	struct gnet_stats_rate_est	rate_est;//¶ÓÁĞµ±Ç°µÄËÙÂÊ£¬°üÀ¨ÒÔ×Ö½ÚºÍ±¨ÎÄÊıÎªµ¥Î»Á½ÖÖ

    /*ÓÃÓÚÊµÏÖ¸ü¸´ÔÓµÄÁ÷Á¿¿ØÖÆ»úÖÆ£¬ºÜÉÙÅÅ¶Ó¹æÔò»áÊµÏÖ´Ë½Ó¿Ú¡£µ±Ò»¸öÍâ²¿¶ÓÁĞÏòÄÚ²¿¶ÓÁĞ
    ´«µİ±¨ÎÄÊ±£¬¿ÉÄÜ³öÏÖ±¨ÎÄ±ØĞë±»¶ªÆúµÄÇé¿ö£¬Èçµ±Ã»ÓĞ¿ÉÓÃ»º³åÇøÊ±¡£Èç¹ûÅÅ¶Ó¹æÔòÊµÏÖÁË¸Ã»Øµ÷
    º¯Êı£¬ÄÇÃ´ÕâÊ±¾Í¿ÉÒÔ±»ÄÚ²¿ÅÅ¶Ó¹æÔòµ÷ÓÃ*/
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);

	void			*u32_node;//Ö¸Ïòtc_u_common£¬¼ûu32_init  Ö¸ÏòµÄÊÇÖ¸¶¨¶ÓÁĞ¹æ³ÌµÄµÚÒ»¸öu32¹ıÂËÆ÷

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;
	struct netdev_queue	*dev_queue;
	struct Qdisc		*next_sched;

	struct sk_buff		*gso_skb;
	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	unsigned long		state;
	struct sk_buff_head	q; //SKB¾ÍÊÇÌí¼Óµ½¸Ã¶ÓÁĞÖĞµÄ  pfifoÊÇÈë¶ÓµÄÊ±ºòÖ±½Ó¼ÓÈë¸ÃskbÁ´±í£¬ËùÒÔÊÇµäĞÍµÄÏÈ½øÏÈ³ö
	struct gnet_stats_basic_packed bstats;//¼ÇÂ¼Èë¶Ó±¨ÎÄ×Ü×Ö½ÚÊıºÍÈë¶Ó±¨ÎÄ×ÜÊı
	struct gnet_stats_queue	qstats;//¼ÇÂ¼¶ÓÁĞÏà¹ØÍ³¼ÆÊı¾İ
	struct rcu_head     rcu_head;//Í¨¹ı±¾×Ö½ÚÔÚÃ»ÓĞ¶ÔÏóÔÙÊ¹ÓÃ¸ÃÅÅ¶Ó¹æÔòÊ±ÊÍ·Å¸ÃÅÅ¶Ó¹æÔò
};

/*
//·ÖÀàµÄ¶ÓÁĞ¹æ¶¨£¬ÀıÈçprio cbq htb£¬ÕâĞ©¶ÓÁĞ¹æÔòQdisc¶¼»á¶ÔÓ¦Ò»¸öÀà½Ó¿Ú£¬Èç¹ûÊÇÎŞÀàµÄ¶ÓÁĞ¹æ¶¨£¬ÔòÃ»ÓĞ¸ÃÀà²Ù×÷½Ó¿Ú
//prio¶ÔÓ¦prio_class_ops htb¶ÔÓ¦htb_class_ops cbq¶ÔÓ¦cbq_class_opsµÈµÈ

//·ÖÀà¶ÓÁĞ¹æ³ÌQdisc opsÖĞµÄQdisc_class_opsÖ÷ÒªÊÇÔÚ´´½¨×ÓQdiscµÄÊ±ºò£¬°´ÕÕparent 22:4ÖĞµÄ22:4¶Ô¸¸Qdisc½øĞĞ·ÖÀà£¬´Ó¶øÍ¨¹ı22:4×÷Îª²ÎÊı£¬
//Ñ¡³ö¸Ã×ÓQdiscÓ¦¸Ã¼Óµ½ÄÇ¸ö·ÖÀàQdiscºóÃæ¡£¿ÉÒÔ²Î¿¼prio_qdisc_opsÖĞµÄprio_getºÍprio_graft£¬¾ÍºÜºÃÃ÷°×ÁË
*/ //´´½¨×Ó¶ÓÁĞ¹æÔò»òÕßclassµÄÊ±ºò£¬¸Ã½á¹¹µÄ×÷ÓÃ¾ÍÊÇÍ¨¹ıparent 22:8ÖĞµÄ8´Óprio_get(ÒÔprio·ÖÀà¶ÓÁĞ¹æ³ÌÎªÀı)Ñ¡³öµÄprize_sizeË½ÓĞÊı¾İ²¿·ÖÊı×éÖĞµÄÄÇÒ»¸ö¾ßÌåĞÅÏ¢£¬
struct Qdisc_class_ops { //Ö÷ÒªÔÚqdisc_graftÖ´ĞĞÏÂÃæµÄÏà¹Øº¯Êı       ¿ÉÒÔ²Î¿¼prio_qdisc_ops£¬ÒÔprioÎªÀı        tc_ctl_tclass
	/* Child qdisc manipulation */
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);

	//º¯Êıqdisc_graftÖĞµ÷ÓÃ
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);¡//ÓÃÓÚ½«Ò»¸ö¶ÓÁĞ¹æÔòQdisc°ó¶¨µ½Ò»¸öÀà£¬²¢·µ»ØÏÈÇ°°ó¶¨µ½Õâ¸öÀàµÄ¶ÓÁĞ¹æÔò
    //»ñÈ¡µ±Ç°°ó¶¨µ½ËùÔÚÀàµÄ¶ÓÁĞ¹æÔò
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);

	//ÓÃÓÚÏàÓ¦¶ÓÁĞ³¤¶È±ä»¯
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
    //¸ù¾İ¸øµãµÄÀàÃèÊö·û´ÓÅÅ¶Ó¹æÔòÖĞ²éÕÒ¶ÔÓ¦µÄÀà£¬²¢ÒıÓÃ¸ÃÀà£¬¸ÃÀàµÄÒıÓÃ¼ÆÊıÔö¡£
    //±íÊ¾Ê¹ÓÃ¶ÓÁĞ¹æ³ÌÀïÃæµÄµÚ¼¸¸ö·ÖÀàĞÅÏ¢£¬Ò»¸ö·ÖÀà¶ÓÁĞ¹æ³ÌÀïÃæ¶¼»áÓĞºÃ¼¸¸ö·ÖÀàĞÅÏ¢£¬Í¨¹ıclassid´ÓÆäÖĞÑ¡Ò»¸ö£¬ÀıÈçprio·ÖÀà¹æ³ÌÍ¨¹ıprio_get»ñÈ¡·ÖÀàÆµµÀÖĞµÄµÚ¼¸¸öÆµµÀ
    //¸ù¾İ¸Ãº¯ÊıÀ´È·¶¨Ê¹ÓÃ¸ÃQdiscµÄÄÇ¸öÀà£¬ÅĞ¶ÏÌõ¼şÎªtc qdisc add dev eth0 parent 22:4 handle 33ÖĞµÄ22:4,ÒÔprio·ÖÀà¶ÓÁĞ¹æ³ÌÎªÀı£¬¼ûprio_get
	unsigned long		(*get)(struct Qdisc *, u32 classid); //Í¨¹ıqdisc_graftµ÷ÓÃ
    //µİ¼õÖ¸¶¨ÀàµÄÒıÓÃ¼ÆÊı£¬Èç¹ûÒıÓÃ¼ÆÊıÎª0£¬ÔòÉ¾³ıÊÍ·Å´ËÀà¡£
	void			(*put)(struct Qdisc *, unsigned long); //º¯Êıqdisc_graftÖĞµ÷ÓÃ
    //ÓÃÓÚ±ä¸üÖ¸¶¨ÀàµÄ²ÎÊı£¬Èç¹û¸ÃÀà²»´æÔÚÔòĞÂ½¨Ö®¡£
	int			(*change)(struct Qdisc *, u32, u32,
					struct nlattr **, unsigned long *);
    //ÓÃÓÚÉ¾³ı²¢ÊÍ·ÅÖ¸¶¨µÄÀà¡£Ê×ÏÈ»áµİ¼õ¸ÃÀàµÄÒıÓÃ¼ÆÊı£¬Èç¹ûÒıÓÃ¼ÆÊıµİ¼õºóÎª0£¬É¾³ıÊÍ·ÅÖ®¡£
	int			(*delete)(struct Qdisc *, unsigned long);
    //±éÀúÒ»¸öÅÅ¶Ó¹æÔòµÄËùÓĞÀà£¬È¡»ØÊµÏÖÁË»Øµ÷º¯ÊıÀàµÄÅäÖÃÊı¾İ¼°Í³¼ÆĞÅÏ¢
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	//»ñÈ¡°ó¶¨µ½¸ÃÀàµÄ¹ıÂËÆ÷ËùÔÚÁ´±íµÄÊ×½Úµã
	struct tcf_proto **	(*tcf_chain)(struct Qdisc *, unsigned long);

    //ÔÚÒ»¸ö¹ıÂËÆ÷Õı×¼±¸°ó¶¨µ½Ö¸¶¨µÄÀàÖ®Ç°±»µ÷ÓÃ£¬Í¨¹ıÀà±êÊ¶·û»ñÈ¡Àà£¬Ê×ÏÈµİÔöÒıÓÃ¼ÆÊı£¬È»ºóÊÇÒ»Ğ©ÆäËûµÄ¼ì²é
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid); //¼ûtcf_bind_filter

    //ÔÚ¹ıÂËÆ÷Íê³É°ó¶¨µ½Ö¸¶¨µÄÀàºó±»µ÷ÓÃ£¬µİ¼õÀàÒıÓÃ¼ÆÊı
    void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

//ËùÓĞµÄQdisc_ops½á¹¹Í¨¹ıregister_qdiscÌí¼Óµ½qdisc_baseÁ´±íÖĞ
//QdiscÖĞµÄopsÖ¸ÏòÕâÀï              /*pfifo_fast_ops pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_ops prio_class_opsÕâ¼¸¸ö¶¼Îª³ö¿Ú£¬ingress_qdisc_opsÎªÈë¿Ú */
struct Qdisc_ops { //prio¶ÓÁĞ¹æÔòopsÎªpfifo_qdisc_ops£¬ÆäËû»¹ÓĞtbf_qdisc_ops sfq_qdisc_opsµÈ£¬ 
	struct Qdisc_ops	*next;//Ö¸ÏòÏÂÒ»¸öQdisc_ops
    //ËùÓĞ¹æÔòÌá¹©µÄÀà²Ù×÷½Ó¿Ú¡£
	const struct Qdisc_class_ops	*cl_ops; //ÎŞÀàµÄ¶ÓÁĞpfifo bfifo¹æÔòÃ»ÓĞclass×ÓÀàops£¬
	char			id[IFNAMSIZ]; //ÅÅ¶Ó¹æÔòÃû
	//¸½ÊôÔÚÅÅ¶Ó¹æÔòÉÏµÄË½ÓĞĞÅÏ¢¿é´óĞ¡£¬¸ÃĞÅÏ¢¿éÍ¨³£ÓëÅÅ¶Ó¹æÔòÒ»Æğ·ÖÅäÄÚ´æ£¬½ô¸úÔÚÅÅ¶Ó
	//¹æÔòºóÃæ£¬¿ÉÓÃqdisc_priv»ñÈ¡£¬ 
	int			priv_size; //±¾Àà¶ÔÏóË½ÓĞÊı¾İ´óĞ¡ Qdisc_alloc¿ª±ÙQdisc¿Õ¼äµÄÊ±ºò»á¶à¿ª±Ùpriv_size¿Õ¼ä

//enqueue·µ»ØÖµNET_XMIT_SUCCESSµÈ
	int 			(*enqueue)(struct sk_buff *, struct Qdisc *); //µ÷ÓÃµØ·½qdisc_enqueue   //dev_xmit_queueÒ»Ö±ÏÂÈ¥µ÷ÓÃ
//½«ÏÈÇ°³ö¶ÓµÄ±¨ÎÄÖØĞÂÅÅÈëµ½¶ÓÁĞÖĞµÄº¯Êı¡£²»Í¬ÓÚenqueueµÄÊÇ£¬ÖØĞÂÈë¶ÓµÄ±¨ÎÄĞèÒª±»·ÅÖÃÔÚËı
//³ö¶ÓÇ°ÔÚÅÅ¶Ó¹æÔò¶ÓÁĞÖĞËù´¦µÄÎ»ÖÃÉÏ¡£¸Ã½Ó¿ÚÍ¨³£ÓÃÓÚ±¨ÎÄÒª·¢ËÍ³öÈ¥¶øÓĞdequeue³ö¶Óºó£¬ÒòÄ³¸ö²»¿ÉÔ¤¼ûµÄÔ­Òò×îÖÕÎ´ÄÜ·¢ËÍµÄÇé¿ö¡£
	struct sk_buff *	(*dequeue)(struct Qdisc *);//dequeue_skbÖĞµ÷ÓÃ
	struct sk_buff *	(*peek)(struct Qdisc *);

	//´Ó¶ÓÁĞÒÆ³ı²¢¶ªÆúÒ»¸ö±¨ÎÄµÄº¯Êı
	unsigned int		(*drop)(struct Qdisc *);

    //ÔÚqdisc_createÖĞµ÷ÓÃ
	int			(*init)(struct Qdisc *, struct nlattr *arg); //¶ÔÏó³õÊ¼»¯º¯Êı  //·ÖÀàµÄ¶ÓÁĞ¹æÔòÔÚ³õÊ¼»¯µÄÊ±ºò»áÄ¬ÈÏÖ¸Ïònoop_qdisc£¬ÀıÈçprio_qdisc_opsÖĞµÄinit
	void			(*reset)(struct Qdisc *); //¸´Î»Îª³õÊ¼×´Ì¬£¬É¾³ı¶¨Ê±Æ÷ ÊÍ·Å¿Õ¼äµÈ
	void			(*destroy)(struct Qdisc *);
	int			(*change)(struct Qdisc *, struct nlattr *arg); //¸ü¸ßQdisc²ÎÊı
	void			(*attach)(struct Qdisc *);


	int			(*dump)(struct Qdisc *, struct sk_buff *);
    //ÓÃÓÚÊä³öÅÅ¶Ó¹æÔòµÄÅäÖÃ²ÎÊıºÍÍ³¼ÆÊı¾İµÄº¯Êı¡£
   	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};

//Í¨¹ı½âÎöSKBÖĞµÄÄÚÈİÀ´Æ¥Åä¹ıÂËÆ÷tc filter£¬Æ¥Åä½á¹û´æµ½¸Ã½á¹¹ÖĞ¡£Ò²¾ÍÊÇÖ±½Ó»ñÈ¡¸Ã¹ıÂËÆ÷ËùÔÚclassµÄ(tc add classµÄÊ±ºò´´½¨µÄclassÊ÷½Úµã)htb_class
struct tcf_result {
	unsigned long	class; //Õâ¸öÊµ¼ÊÉÏÊÇÒ»¸öÖ¸ÕëµØÖ·£¬Ö¸ÏòµÄÊÇtc filter add xxxx flowid 22:4¶ÔÓ¦µÄhtb_class½á¹¹£¬¼ûtcf_bind_filter
	u32		classid;//¼ûu32_set_parms£¬¸ÃÖµÎª//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4ÖĞµÄflowid£¬±íÊ¾¸Ã¹ıÂËÆ÷ÊôÓÚÄÇ¸ö¶ÓÁĞ¹æ³ÌÊ÷½Úµã
};

//tcf_protoÖĞµÄops£¬ËùÓĞµÄtcf_proto_opsÍ¨¹ıtcf_proto_baseÁ¬½ÓÔÚÒ»Æğ£¬¼ûregister_tcf_proto_ops
//Ö÷ÒªÓĞcls_u32_ops cls_basic_ops  cls_cgroup_ops  cls_flow_ops cls_route4_ops RSVP_OPS
struct tcf_proto_ops {
	struct tcf_proto_ops	*next; //ÓÃÀ´½«ÒÑ×¢²á¹ıÂËÆ÷Á¬½Óµ½tcf_proto_baseÁ´±íÉÏµÄÖ¸Õë
	char			kind[IFNAMSIZ];//¹ıÂËÆ÷ÀàÃû 

	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *); //·ÖÀàº¯Êı£¬½á¹û±£´æÔÚtcf_resultÖĞ£¬·µ»ØÖµÓĞTC_POLICE_OKµÈ
	int			(*init)(struct tcf_proto*); //tc_ctl_tclassÖĞµ÷ÓÃ

    //ÊÍ·Å²¢É¾³ı¹ıÂËÆ÷º¯Êı
	void			(*destroy)(struct tcf_proto*);

    //½²Ò»¸ö¹ıÂËÆ÷ÔªËØµÄ¾ä±úÓ³Éäµ½Ò»¸öÄÚ²¿¹ıÂËÆ÷±êÊ¶·û£¬Êµ¼ÊÉÏÊÇ¹ıÂËÆ÷ÊµÀıÖ¸Õë£¬²¢½«Æä·µ»Ø
	unsigned long		(*get)(struct tcf_proto*, u32 handle); //»ñÈ¡¶ÔÓ¦µÄ¹ıÂËÆ÷
    //ÊÍ·Å¶ÔgetµÃµ½µÄ¹ıÂËÆ÷µÄÒıÓÃ
	void			(*put)(struct tcf_proto*, unsigned long);
	//ÓÃÓÚÅäÖÃÒ»¸öĞÂ¹ıÂËÆ÷»òÊÇ±ä¸üÒ»¸öÒÑ´æÔÚµÄ¹ıÂËÆ÷ÅäÖÃ¡£
	int			(*change)(struct tcf_proto*, unsigned long,
					u32 handle, struct nlattr **,
					unsigned long *);
	int			(*delete)(struct tcf_proto*, unsigned long);
    //±éÀúËùÓĞµÄÔªËØ²¢ÇÒµ÷ÓÃ»Øµ÷º¯ÊıÈ¡µÃÅäÖÃÊı¾İºÍÍ³¼ÆÊı¾İ
	void			(*walk)(struct tcf_proto*, struct tcf_walker *arg);

	/* rtnetlink specific */  //ÓÃÓÚÊä³öËùÓĞµÄÔªËØ²¢ÇÒµ÷ÓÃ»Øµ÷º¯ÊıÈ¡µÃÅäÖÃÊı¾İºÍÍ³¼ÆÊı¾İ
	int			(*dump)(struct tcf_proto*, unsigned long,
					struct sk_buff *skb, struct tcmsg*);

	struct module		*owner;
};
/* ÓÅÏÈ¼¶¶ÓÁĞ¹æ¶¨µÄbandÎª16¸ö,²Î¿¼TCÁ÷Á¿¿ØÖÆÊµÏÖ·ÖÎö(³õ²½)-Í¼3  ½¨Á¢¡±prio¡±ÀàĞÍµÄ¸ùÁ÷¿Ø¶ÔÏó_2 */   //ÏêÏ¸Àí½âÒ²¿ÉÒÔ²Î¿¼<<LINUX¸ß¼¶Â·ÓÉºÍÁ÷Á¿¿ØÖÆ>>
//tc filter add dev eth0 protocol ip parent 22: prio 2 u32 match ip dst 4.3.2.1/32 flowid 22:4
/*ÏÖÔÚÊı¾İ°üµÄÈë¶ÓÁ÷³ÌÈçÏÂ£º
1.      ¸ù¶ÔÏóµÄ¹ıÂËÆ÷Á´·Ç¿Õ£¬±éÀú¸ù¶ÔÏóµÄ¹ıÂËÆ÷Á´£¬Óöµ½µÚÒ»¸öÆ¥ÅäµÄ¹ıÂËÆ÷¾Í·µ»Ø£¬²¢¸ù¾İ·µ»ØµÄ½á¹ûÑ¡Ôñ×ÓÀà¡£
2.      Ã¿¸ö¹ıÂËÆ÷¶¼µ÷ÓÃÏàÓ¦µÄ·ÖÀàº¯Êı£¬²¢¸ù¾İ¹ıÂËÆ÷µÄË½ÓĞÊı¾İÀ´Æ¥ÅäÊı¾İ°ü¡£
*/
//tc filter u32¹ıÂËÆ÷µÄ½á¹¹    ¹ıÂËÆ÷´´½¨ÔÚtc_ctl_tfilterÖĞ£¬²¢ÔÚ¸Ãº¯ÊıÖĞ³õÊ¼»¯
struct tcf_proto { //¸Ã½á¹¹ÊÇ¼ÓÈëµ½prio_sched_dataÖĞµÄfilter_listÁ´±íÖĞ  Ã¿µ÷ÓÃÒ»´Îtc filter add¾Í»á´´½¨Ò»¸ötcf_proto½á¹¹£¬µ÷ÓÃ¶à¸ötc filter addµÄÊ±ºò¾Í´´½¨¶à¸ötcf_proto½á¹¹£¬Í¨¹ınextÁ¬½Ó
	/* Fast access part */ //tcfÒ»°ã±íÊ¾tcf_proto¹ıÂËÆ÷µÄ¼òĞ´
	struct tcf_proto	*next;
	void			*root; //Èç¹ûÎªu32ÀàĞÍ£¬Ö¸Ïò¹ıÂËÆ÷¸útc_u_hnode£¬ ¼ûu32_init£¬¸Ã¹ıÂËÆ÷ÏÂÃæµÄËùÓĞtc_u_common½Úµã¶¼Ìí¼Óµ½¸Ãtc_u_hnode¸úÉÏ
	int			(*classify)(struct sk_buff*, struct tcf_proto*,
					struct tcf_result *); //·ÖÀàº¯Êı£¬½á¹û±£´æÔÚtcf_resultÖĞ¡£Í¨¹ıSKBÖĞµÄÄÚÈİ£¬À´Æ¥ÅäÕâ¸ö¹ıÂËÆ÷£¬½á¹û·µ»Ø¸øtcf_result£¬¼ûtc_classify_compat
	__be16			protocol; //Ğ­ÒéºÅ£¬//tc filter add dev eth0 protocol ipÖĞprotocol ip¶ÔÓ¦µÄÊÇÊı×ÖETH_P_IP

	/* All the rest */
	u32			prio; //¸ù¾İÕâ¸öÓÅÏÈ¼¶¼ÓÈëµ½prio_sched_dataÖĞµÄfilter_listÁ´±íÖĞ¡£tc filter add dev eth0 protocol ip parent 22: prio 2Îª2
	u32			classid; //Ö¸¶¨¸¸QdiscÖĞµÄ×ÓÀàÎ»ÖÃ=22:4
	struct Qdisc		*q; //¸¸Qdisc,¾ÍÊÇ¸Ã¹ıÂËÆ÷Ëù´¦µÄ¶ÓÁĞ¹æÔò½ÚµãµÄÉÏ¼¶¸¸Qdisc
	void			*data; //Èç¹û×îºó´´½¨µÄu32ÀàĞÍ¹ıÂËÆ÷½Úµãtc_u_common£¬¼ûu32_init
	struct tcf_proto_ops	*ops; //cls_u32_ops //Ö÷ÒªÓĞcls_u32_ops cls_basic_ops  cls_cgroup_ops  cls_flow_ops cls_route4_ops RSVP_OPS
};

struct qdisc_skb_cb {
	unsigned int		pkt_len;//¼ûqdisc_enqueue_root£¬µ±Èë¶ÓµÄÊ±ºò£¬¸ÃÖµÎªSKB->len
	char			data[];
};

static inline int qdisc_qlen(struct Qdisc *q)
{
	return q->q.qlen;
}

static inline struct qdisc_skb_cb *qdisc_skb_cb(struct sk_buff *skb)
{
	return (struct qdisc_skb_cb *)skb->cb;
}

static inline spinlock_t *qdisc_lock(struct Qdisc *qdisc)
{
	return &qdisc->q.lock;
}

static inline struct Qdisc *qdisc_root(struct Qdisc *qdisc)
{
	return qdisc->dev_queue->qdisc;
}

static inline struct Qdisc *qdisc_root_sleeping(struct Qdisc *qdisc)
{
	return qdisc->dev_queue->qdisc_sleeping;
}

/* The qdisc root lock is a mechanism by which to top level
 * of a qdisc tree can be locked from any qdisc node in the
 * forest.  This allows changing the configuration of some
 * aspect of the qdisc tree while blocking out asynchronous
 * qdisc access in the packet processing paths.
 *
 * It is only legal to do this when the root will not change
 * on us.  Otherwise we'll potentially lock the wrong qdisc
 * root.  This is enforced by holding the RTNL semaphore, which
 * all users of this lock accessor must do.
 */
static inline spinlock_t *qdisc_root_lock(struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline spinlock_t *qdisc_root_sleeping_lock(struct Qdisc *qdisc)
{
	struct Qdisc *root = qdisc_root_sleeping(qdisc);

	ASSERT_RTNL();
	return qdisc_lock(root);
}

static inline struct net_device *qdisc_dev(struct Qdisc *qdisc)
{
	return qdisc->dev_queue->dev;
}

static inline void sch_tree_lock(struct Qdisc *q)
{
	spin_lock_bh(qdisc_root_sleeping_lock(q));
}

static inline void sch_tree_unlock(struct Qdisc *q)
{
	spin_unlock_bh(qdisc_root_sleeping_lock(q));
}

#define tcf_tree_lock(tp)	sch_tree_lock((tp)->q)
#define tcf_tree_unlock(tp)	sch_tree_unlock((tp)->q)

extern struct Qdisc noop_qdisc;
extern struct Qdisc_ops noop_qdisc_ops;
extern struct Qdisc_ops pfifo_fast_ops;
extern struct Qdisc_ops mq_qdisc_ops;

//¸Ã½á¹¹Îªhtb_class -> common
struct Qdisc_class_common {//´æ·ÅÔÚQdisc_class_hashÖĞ, ±äÁ¿classÔÚqdisc_class_find
	u32			classid;// Àà±ğIDÖµ, ¸ß16Î»ÓÃÓÚÇø·Ö²»Í¬µÄHTBÁ÷¿Ø, µÍ16Î»ÎªÇø·ÖÍ¬Ò»HTBÁ÷¿ØÖĞµÄ²»Í¬Àà±ğ
	struct hlist_node	hnode; //Í¨¹ıÕâ¸öhnode×îÖÕ°Ñhtb_class¼ÓÈëµ½htb_sched->clhashÖĞ£¬¼ûhtb_change_class -> qdisc_class_hash_insert
};

//¸Ã½á¹¹ÎªhtbË½ÓĞÊı¾İhtb_schedÖĞµÄclhash£¬ÓÃÀ´´æ´¢ËùÓĞtc class add´´½¨µÄhtb_class
struct Qdisc_class_hash { //hash¹ı³Ì¼ûqdisc_class_hash_grow
	struct hlist_head	*hash;//¸ÃÁ´±íÖĞ´æ·ÅµÄÊÇQdisc_class_common,¸Ãhash±í¿Õ¼äÔÚqdisc_class_hash_init´´½¨     qdisc_class_find
	unsigned int		hashsize; //Ä¬ÈÏ³õÊ¼Öµ¼ûqdisc_class_hash_init¡£Èç¹ûhash½ÚµãÊıhashelems³¬¹ıÉèÖÃµÄhashsizeµÄ0.75£¬Ôò´ÓĞÂhash£¬hashsizeÀ©´óµ½Ö®Ç°hashsizeÁ½±¶£¬¼ûqdisc_class_hash_grow
	unsigned int		hashmask;  //qdisc_class_hash_init
	unsigned int		hashelems; //Êµ¼ÊµÄhash class½ÚµãÊı //hashelemsºÍhashsize¹ØÏµ¼ûqdisc_class_hash_grow
};

static inline unsigned int qdisc_class_hash(u32 id, u32 mask)
{
	id ^= id >> 8;
	id ^= id >> 4;
	return id & mask;
}

//²éÕÒ
static inline struct Qdisc_class_common *
qdisc_class_find(struct Qdisc_class_hash *hash, u32 id)
{
	struct Qdisc_class_common *cl;
	struct hlist_node *n;
	unsigned int h;

	h = qdisc_class_hash(id, hash->hashmask);
	hlist_for_each_entry(cl, n, &hash->hash[h], hnode) {// ¸ù¾İ¾ä±ú¼ÆËã¹şÏ£Öµ, È»ºó±éÀú¸Ã¹şÏ£Á´±í
		if (cl->classid == id)
			return cl;
	}
	return NULL;
}

extern int qdisc_class_hash_init(struct Qdisc_class_hash *);
extern void qdisc_class_hash_insert(struct Qdisc_class_hash *, struct Qdisc_class_common *);
extern void qdisc_class_hash_remove(struct Qdisc_class_hash *, struct Qdisc_class_common *);
extern void qdisc_class_hash_grow(struct Qdisc *, struct Qdisc_class_hash *);
extern void qdisc_class_hash_destroy(struct Qdisc_class_hash *);

extern void dev_init_scheduler(struct net_device *dev);
extern void dev_shutdown(struct net_device *dev);
extern void dev_activate(struct net_device *dev);
extern void dev_deactivate(struct net_device *dev);
extern struct Qdisc *dev_graft_qdisc(struct netdev_queue *dev_queue,
				     struct Qdisc *qdisc);
extern void qdisc_reset(struct Qdisc *qdisc);
extern void qdisc_destroy(struct Qdisc *qdisc);
extern void qdisc_tree_decrease_qlen(struct Qdisc *qdisc, unsigned int n);
extern struct Qdisc *qdisc_alloc(struct netdev_queue *dev_queue,
				 struct Qdisc_ops *ops);
extern struct Qdisc *qdisc_create_dflt(struct net_device *dev,
				       struct netdev_queue *dev_queue,
				       struct Qdisc_ops *ops, u32 parentid);
extern void qdisc_calculate_pkt_len(struct sk_buff *skb,
				   struct qdisc_size_table *stab);
extern void tcf_destroy(struct tcf_proto *tp);
extern void tcf_destroy_chain(struct tcf_proto **fl);

/* Reset all TX qdiscs greater then index of a device.  */
static inline void qdisc_reset_all_tx_gt(struct net_device *dev, unsigned int i)
{
	struct Qdisc *qdisc;

	for (; i < dev->num_tx_queues; i++) {
		qdisc = netdev_get_tx_queue(dev, i)->qdisc;
		if (qdisc) {
			spin_lock_bh(qdisc_lock(qdisc));
			qdisc_reset(qdisc);
			spin_unlock_bh(qdisc_lock(qdisc));
		}
	}
}

static inline void qdisc_reset_all_tx(struct net_device *dev)
{
	qdisc_reset_all_tx_gt(dev, 0);
}

/* Are all TX queues of the device empty?  */
static inline bool qdisc_all_tx_empty(const struct net_device *dev)
{
	unsigned int i;
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		const struct Qdisc *q = txq->qdisc;

		if (q->q.qlen)
			return false;
	}
	return true;
}

/* Are any of the TX qdiscs changing?  */
static inline bool qdisc_tx_changing(struct net_device *dev)
{
	unsigned int i;
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (txq->qdisc != txq->qdisc_sleeping)
			return true;
	}
	return false;
}

/* Is the device using the noop qdisc on all queues?  */
static inline bool qdisc_tx_is_noop(const struct net_device *dev)
{
	unsigned int i;
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (txq->qdisc != &noop_qdisc)
			return false;
	}
	return true;
}

static inline unsigned int qdisc_pkt_len(struct sk_buff *skb)
{
	return qdisc_skb_cb(skb)->pkt_len;
}

/* additional qdisc xmit flags (NET_XMIT_MASK in linux/netdevice.h) */
enum net_xmit_qdisc_t {
	__NET_XMIT_STOLEN = 0x00010000,
	__NET_XMIT_BYPASS = 0x00020000,
};

#ifdef CONFIG_NET_CLS_ACT
#define net_xmit_drop_count(e)	((e) & __NET_XMIT_STOLEN ? 0 : 1)
#else
#define net_xmit_drop_count(e)	(1)
#endif


static inline int qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
#ifdef CONFIG_NET_SCHED
	if (sch->stab)
		qdisc_calculate_pkt_len(skb, sch->stab);
#endif
	return sch->enqueue(skb, sch);///*prio_qdisc_ops pfifo_qdisc_ops tbf_qdisc_ops sfq_qdisc_opsÕâ¼¸¸ö¶¼Îª³ö¿Ú£¬ingress_qdisc_opsÎªÈë¿Ú */
}

//ingressÍ¨¹ıing_filterÈë¶Ó
static inline int qdisc_enqueue_root(struct sk_buff *skb, struct Qdisc *sch) //sch devÉè±¸µÄqdisc
{
	qdisc_skb_cb(skb)->pkt_len = skb->len;
	return qdisc_enqueue(skb, sch) & NET_XMIT_MASK;
}

static inline void __qdisc_update_bstats(struct Qdisc *sch, unsigned int len)
{
	sch->bstats.bytes += len;
	sch->bstats.packets++;
}

static inline int __qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	__skb_queue_tail(list, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	__qdisc_update_bstats(sch, qdisc_pkt_len(skb));

	return NET_XMIT_SUCCESS;
}

static inline int qdisc_enqueue_tail(struct sk_buff *skb, struct Qdisc *sch)
{
	return __qdisc_enqueue_tail(skb, sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_head(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= qdisc_pkt_len(skb);

	return skb;
}

//__qdisc_run -> qdisc_restart -> dequeue_skb -> prio_dequeue(ÕâÀïÃæÓĞ¸öµİ¹éµ÷ÓÃ¹ı³Ì) -> qdisc_dequeue_head
static inline struct sk_buff *qdisc_dequeue_head(struct Qdisc *sch)
{
	return __qdisc_dequeue_head(sch, &sch->q);
}

static inline unsigned int __qdisc_queue_drop_head(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __qdisc_dequeue_head(sch, list);

	if (likely(skb != NULL)) {
		unsigned int len = qdisc_pkt_len(skb);
		kfree_skb(skb);
		return len;
	}

	return 0;
}

static inline unsigned int qdisc_queue_drop_head(struct Qdisc *sch)
{
	return __qdisc_queue_drop_head(sch, &sch->q);
}

static inline struct sk_buff *__qdisc_dequeue_tail(struct Qdisc *sch,
						   struct sk_buff_head *list)
{
	struct sk_buff *skb = __skb_dequeue_tail(list);

	if (likely(skb != NULL))
		sch->qstats.backlog -= qdisc_pkt_len(skb);

	return skb;
}

static inline struct sk_buff *qdisc_dequeue_tail(struct Qdisc *sch)
{
	return __qdisc_dequeue_tail(sch, &sch->q);
}

static inline struct sk_buff *qdisc_peek_head(struct Qdisc *sch)
{
	return skb_peek(&sch->q);
}

/* generic pseudo peek method for non-work-conserving qdisc */
static inline struct sk_buff *qdisc_peek_dequeued(struct Qdisc *sch)
{
	/* we can reuse ->gso_skb because peek isn't called for root qdiscs */
	if (!sch->gso_skb) {
		sch->gso_skb = sch->dequeue(sch);
		if (sch->gso_skb)
			/* it's still part of the queue */
			sch->q.qlen++;
	}

	return sch->gso_skb;
}

/* use instead of qdisc->dequeue() for all qdiscs queried with ->peek() */
static inline struct sk_buff *qdisc_dequeue_peeked(struct Qdisc *sch)
{
	struct sk_buff *skb = sch->gso_skb;

	if (skb) {
		sch->gso_skb = NULL;
		sch->q.qlen--;
	} else {
		skb = sch->dequeue(sch);
	}

	return skb;
}

static inline void __qdisc_reset_queue(struct Qdisc *sch,
				       struct sk_buff_head *list)
{
	/*
	 * We do not know the backlog in bytes of this list, it
	 * is up to the caller to correct it
	 */
	__skb_queue_purge(list);
}

static inline void qdisc_reset_queue(struct Qdisc *sch)
{
	__qdisc_reset_queue(sch, &sch->q);
	sch->qstats.backlog = 0;
}

static inline unsigned int __qdisc_queue_drop(struct Qdisc *sch,
					      struct sk_buff_head *list)
{
	struct sk_buff *skb = __qdisc_dequeue_tail(sch, list);

	if (likely(skb != NULL)) {
		unsigned int len = qdisc_pkt_len(skb);
		kfree_skb(skb);
		return len;
	}

	return 0;
}

//¶ªÆúqdiscÅÅ¶Ó¹æ³Ìskb¶ÓÁĞÉÏµÄÊı¾İ
static inline unsigned int qdisc_queue_drop(struct Qdisc *sch)
{
	return __qdisc_queue_drop(sch, &sch->q);
}

static inline int qdisc_drop(struct sk_buff *skb, struct Qdisc *sch)
{
	kfree_skb(skb);
	sch->qstats.drops++;

	return NET_XMIT_DROP;
}

static inline int qdisc_reshape_fail(struct sk_buff *skb, struct Qdisc *sch)
{
	sch->qstats.drops++;

#ifdef CONFIG_NET_CLS_ACT
	if (sch->reshape_fail == NULL || sch->reshape_fail(skb, sch))
		goto drop;

	return NET_XMIT_SUCCESS;

drop:
#endif
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

/*
å«º£ÊéÏã Ëµ

ÄÇ¸ö´óÏº¸ø½²½âÒ»ÏÂ½á¹¹
qdisc_rate_table{
  struct tc_ratespec rate;
  u32 data[256];
  struct qdisc_rate_table *next;
  int refcnt;
}
×î½üÔÚ¿´Á÷¿ØÔ´Âë£¬¿´µ½tbfÊ±£¬×ÜÊÇ¿´²»¶®Õâ¸öµØ·½¡£
»¹ÓĞ¾ÍÊÇ
    qdisc_l2t()ÊÇÔõÃ´ËãµÄ°¡¡£ÔõÃ´¾ÍÊÇ¿´²»¶®ÄØ£¿
Ï£Íû¶®µÄ´óÏº¸ø½²½âÒ»ÏÂ£¬Ğ¡µÜÏÈĞ»Ğ»ÁË
emmoblin Ëµ

ºÇºÇ£¬Õâ¸öÎÒ¿´ÁËÏàµ±Ò»¶ÎÊ±¼ä²Å¿´Ã÷°×¡£

Õâ¸ö½á¹¹Ö÷ÒªÊÇÓÃÀ´ÔÚÄÚºË¼ÆËãÁîÅÆÊ±ÓÃµÄ¡£
ÎÒÄÜÀí½â£¬²»¹ıÎÒÓĞµãËµ²»Ã÷°×¡£
ÄÚºËµÄ×îĞ¡µ÷¶Èµ¥Î»ÊÇÒ»¸ötick¡£ËùÒÔÄÚºËÒª°ÑÊÀ½çÊ±¼ä×ª»¯ÎªÄÚºËµÄtickÊ±¼ä¡£
ÄãÔÚºÃºÃÌå»áÒ»ÏÂ£¬¾ÍÏàµ±ÓÚÊÇÒ»¸ö»ãÂÊ£¬ÊÀ½çÊ±¼äµÄ100ms£¬×ª»»µ½ÄÚºËtickÊ±¼äÊÇÒª³ÉÒ»¸öÏµÊıµÄ¡£



£¨Ò»£©¿ÕÏĞ×ÊÔ´Á÷¿ØËã·¨
Ëã·¨¸ÅÊö£ºµ¥Î»Ê±¼äÄÚ²úÉúµÄ¿ÕÏĞ×ÊÔ´Ò»¶¨£¬Ã¿·¢ËÍÒ»¸ö×Ö½Ú¶¼ÒªÏûºÄÏàÓ¦´óĞ¡µÄ¿ÕÏĞ×ÊÔ´£¬µ±¿ÕÏĞ×ÊÔ´²»×ãÊ±Í£Ö¹·¢ËÍÊı¾İ°ü£¬Éè¶¨µÄÁ÷ËÙÔ½´ó£¬
·¢ËÍÒ»¸ö×Ö½ÚËùÏûºÄµÄ¿ÕÏĞ×ÊÔ´¾ÍÔ½Ğ¡£¬Í¨¹ıÉèÖÃ·¢ËÍÒ»¸ö×Ö½ÚËùÏûºÄµÄ¿ÕÏĞ×ÊÔ´À´½øĞĞÁ÷ËÙ¿ØÖÆ¡£

»ù±¾¸ÅÄî:

1. ¿ÕÏĞ×ÊÔ´£º·¢ËÍÒ»¸öÊı¾İ°ü¶¼±ØĞëÏûºÄ¿ÕÏĞ×ÊÔ´£¬Èç¹ûÄ³¸ö¶ÔÏóµÄ¿ÕÏĞ×ÊÔ´Îª0£¬½«ÎŞ·¨·¢ËÍÊı¾İ°ü£¬Ö»Òª¿ÕÏĞ×ÊÔ´×ã¹»¶à¾Í¿ÉÒÔ·¢ËÍÊı¾İ°ü¡£
(TCÓÃ»§¿Õ¼ä¹æÔò¶¨Ã¿Ãë²úÉúµÄ¿ÕÏĞ×ÊÔ´ÊÇTIME_UNITS_PER_SEC       1000000£¬¶øTCÄÚºË¸ù¾İ¿ÕÏĞÊ±¼äÀ´¼ÆËã¿ÕÏĞ×ÊÔ´¡£)

2.¿ÕÏĞÊ±¼ä£º¼ÙÉè¶ÔÏó×î½üÒ»´Î·¢ËÍÊı¾İ°üµÄÊ±¿ÌÊÇT1£¬ÏµÍ³µ±Ç°µÄÊ±¿ÌÊÇT2£¬Ôò¿ÕÏĞÊ±¼ätk = T1 ¨C T2¡£

2. Á÷ËÙrate£ºÃ¿ÃëÔÊĞí·¢ËÍµÄµÄ×Ö½Ú¸öÊı¡£
3. ¿ÕÏĞ×ÊÔ´»ıÀÛÁ¿£ºÒÔ¿ÕÏĞÊ±¼äÎª²ÎÊı¸ù¾İÒ»¶¨µÄËã·¨µÃµ½µÄÖµ£¨±ÈÈç¿ÉÒÔ½«¿ÕÏĞÊ±¼ä³ËÉÏÒ»¸öÕıÊı£©£¬µ«ÊÇÒª±£Ö¤¿ÕÏĞÊ±¼äÔ½´ó£¬¶ÔÓ¦µÄ¿ÕÏĞ×ÊÔ´µÄ»ıÀÛÁ¿±Ø¶¨ÒªÔ½´ó¡£
4. ¿ÕÏĞ×ÊÔ´Ê£ÓàÁ¿£º×î½üÒ»´Î·¢ËÍÊı¾İ°üÒÔºó£¬¿ÕÏĞ×ÊÔ´µÄÊ£ÓàÁ¿¡£
5. µ±Ç°¿ÉÓÃ¿ÕÏĞ×ÊÔ´£ºÒÔ¿ÕÏĞ×ÊÔ´µÄÊ£ÓàÁ¿ºÍ¿ÕÏĞ×ÊÔ´µÄ»ıÀÛÁ¿Îª²ÎÊı¸ù¾İÒ»¶¨µÄËã·¨µÃµ½µÄÖµ£¨±ÈÈç¿ÉÒÔ = 1/6¿ÕÏĞ×ÊÔ´µÄÊ£ÓàÁ¿ + (1 ¨C 1/6)¿ÕÏĞ×ÊÔ´µÄ»ıÀÛ£©£¬
µ«ÊÇÒª±£Ö¤µ±Ç°¿ÉÓÃ¿ÕÏĞ×ÊÔ´¶¼ÊÇ¿ÕÏĞ×ÊÔ´Ê£ÓàÁ¿ºÍ¿ÕÏĞ×ÊÔ´»ıÀÛÁ¿µÄµİÔöº¯Êı¡£

ÎªÁË¸üºÃµÄÀí½â¿ÕÏĞ×ÊÔ´Á÷¿ØËã·¨£¬ĞèÒªÒıÈëÁ÷ËÙ¸ÅÄîµÄµÚ¶şÖÖÃèÊö£¬Ò²¾ÍÊÇ£¬Ê¹ÓÃ¿ÕÏĞ×ÊÔ´À´ÃèÊöÁ÷ËÙµÄ¸ÅÄî¡£
 

6.Á÷ËÙkc(ÓÃ¿ÕÏĞ×ÊÔ´ÃèÊö)£º¼ÙÉèÃ¿Ãë²úÉúµÄ¿ÕÏĞ×ÊÔ´ÊÇTIME_UNITS_PER_SEC£¬Á÷ËÙrate(Ã¿ÃëÔÊĞí·¢ËÍµÄÊı¾İÁ¿ÊÇrate¸ö×Ö½Ú)£¬Ôò·¢ËÍÒ»¸ö×Ö½ÚµÄÁ÷Á¿ĞèÒªÏûºÄµÄ
¿ÕÏĞ×ÊÔ´ÊÇkc = TIME_UNITS_PER_SEC/rate
ÕâÀïµÄkc¾ÍÊÇĞÂÒıÈëµÄÁ÷ËÙÃèÊö·½·¨¡£Á÷ËÙrateÔ½´ó£¬kc¾ÍÔ½Ğ¡¡£

Èç¹ûÒª·¢ËÍsize×Ö½ÚµÄÊı¾İ°üĞèÒªÏûºÄsize*(TIME_UNITS_PER_SEC/rate)µÄ¿ÕÏĞ×ÊÔ´¡£

Ö»Òª¿ÕÏĞ×ÊÔ´×ã¹»¶à£¬¾Í¿ÉÒÔ·¢ËÍÊı¾İ°ü£¬Ã¿·¢ËÍÒ»¸öÊı¾İ°ü£¬¿ÕÏĞ×ÊÔ´¼õÈ¥ÏàÓ¦µÄÏûºÄÁ¿¡£

Ö»Òª¿ÕÏĞÊ±¼äÒ»Ö±ÀÛ»ı£¬¿ÕÏĞ×ÊÔ´½«»á±äµÃºÜ´ó£¬ÕâÊ±¾ÍÊ§È¥ÁËµ÷¿ØÁ÷ËÙµÄÒâÒå£¬ËùÒÔÒıÈë×î´ó¿ÕÏĞ×ÊÔ´£¬ÒÔÊ¹¿ÕÏĞ×ÊÔ´²»»áÌ«´ó¡£

µ÷¿ØÁ÷ËÙµÄ¹ı³Ì£º
¼ÙÉèÖ»Òª¿ÕÏĞ×ÊÔ´·ÇÁã£¬¾ÍÊÔÍ¼·¢ËÍÒ»¸ö³¤¶ÈÊÇLµÄÊı¾İ°ü£¬Á÷ËÙÊÇkc¡£
1.      ³õÊ¼Ê±¿Ì¿ÕÏĞ×ÊÔ´ºÍ¿ÕÏĞÊ±¼ä¶¼Îª0£¬ÏÔÈ»²»ÔÊĞí·¢ËÍÊı¾İ°ü¡£
2.      ĞİÃßÒ»¶ÎÊ±¼ä£¬¿ÕÏĞÊ±¼ä´óÓÚ0£¬¼ÆËã¿ÕÏĞ×ÊÔ´ÀÛ»ıÁ¿£¬²¢¼ÆËãµ±Ç°¿ÉÓÃ¿ÕÏĞ×ÊÔ´tu¡£
3.      ¼ÆËãL³¤¶ÈµÄÊı¾İ°üĞèÒªÏûºÄkc*LµÄ¿ÕÏĞ×ÊÔ´£¬Èç¹ûtu > a*L£¬·¢ËÍÊı¾İ°ü£¬·ñÔòÔÙĞİÃßÒ»¶ÎÊ±¼ä¡£
4.      ·¢ËÍÊı¾İ°üºó¼õÉÙ¿ÕÏĞ×ÊÔ´£ºtu = tu ¨C a*L£¬Èç¹ûtu > 0£¬ÖØ¸´3µÄ¹ı³Ì£¬Ö±µ½ÔÙ´ÎĞİÃß¡£
5.      ×îÀíÏëµÄ×´Ì¬ÊÇ£º×ÜÊÇ³ÉÁ¢ts = a*L¡£

»ù±¾ÉÏÊ±¿ÉÒÔ´ïµ½µ÷¿ØµÄÄ¿µÄ£¬µ«ÊÇ½á¹ûÊÇ²»×¼È·µÄ£¬ÏàÍ¬µÄËã·¨£¬ÏàÍ¬µÄ²ÎÊı£¬ÔÚ²»Í¬µÄÍøÂç»·¾³£¨Ö÷ÒªÊÇÓ²¼şµÄÅäÖÃ²»Í¬£©ÖĞÁ÷¿ØµÄ½á¹û¿Ï¶¨²»Í¬¡£
µ«ÊÇ¿ÉÒÔ¸ù¾İ¾ßÌåµÄÍøÂç»·¾³£¬À´Ñ¡ÔñÊÊµ±µÄ²ÎÊıÀ´Ìá¸ßËã·¨µÄ×¼È·¶È¡£
¿ÉÒÔµ÷ÕûµÄ²ÎÊıÓĞÁ½Àà£º1. Ëã·¨²ÎÊı£¬2. ÅäÖÃ²ÎÊı¡£
¿Éµ÷ÕûËã·¨²ÎÊıÓĞ£º1. ¿ÕÏĞÊ±¼äºÍ¿ÕÏĞ×ÊÔ´µÄ»»Ëã²ÎÊı 2. Ã¿Ãë¿É²úÉúµÄ¿ÕÏĞ×ÊÔ´TIME_UNITS_PER_SEC¡£

*/
/* Length to Time (L2T) lookup in a qdisc_rate_table, to determine how
   long it will take to send a packet given its size.
 
 */ // ½«³¤¶È×ª»»ÎªÁîÅÆÊı ²Î¿¼<£¨Ò»£©¿ÕÏĞ×ÊÔ´Á÷¿ØËã·¨>  ²Î¿¼Ó¦ÓÃ²ãtc_calc_rtable   
static inline u32 qdisc_l2t(struct qdisc_rate_table* rtab, unsigned int pktlen) //±íÊ¾·¢ËÍptklen³¤¶ÈĞèÒªÏûºÄ¶àÉÙ¿ÕÏĞ×ÊÔ´Ê±¼ä
{
	int slot = pktlen + rtab->rate.cell_align + rtab->rate.overhead;// ¸ù¾İ´óĞ¡¼ÆËãºÏÊÊµÄ²ÛÎ»
	if (slot < 0)
		slot = 0;
	slot >>= rtab->rate.cell_log;
	if (slot > 255)// Èç¹û³¬¹ıÁË255, ÏŞÖÆÎª255
		return (rtab->data[255]*(slot >> 8) + rtab->data[slot & 0xFF]);
	return rtab->data[slot];//Ä¬ÈÏÇé¿öÏÂ//ÕâÀïµÃµ½µÄ¾ÍÊÇ2047¸ö×Ö½ÚËùÏûºÄµÄ¿ÕÏĞ×ÊÔ´¡£
}

#ifdef CONFIG_NET_CLS_ACT
static inline struct sk_buff *skb_act_clone(struct sk_buff *skb, gfp_t gfp_mask)
{
	struct sk_buff *n = skb_clone(skb, gfp_mask);

	if (n) {
		n->tc_verd = SET_TC_VERD(n->tc_verd, 0);
		n->tc_verd = CLR_TC_OK2MUNGE(n->tc_verd);
		n->tc_verd = CLR_TC_MUNGED(n->tc_verd);
	}
	return n;
}
#endif

#endif

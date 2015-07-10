/*
 * 	NET3	Protocol independent device support routines.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Derived from the non IP parts of dev.c 1.0.19
 * 		Authors:	Ross Biro
 *				Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *				Mark Evans, <evansmp@uhura.aston.ac.uk>
 *
 *	Additional Authors:
 *		Florian la Roche <rzsfl@rz.uni-sb.de>
 *		Alan Cox <gw4pts@gw4pts.ampr.org>
 *		David Hinds <dahinds@users.sourceforge.net>
 *		Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 *		Adam Sulmicki <adam@cfar.umd.edu>
 *              Pekka Riikonen <priikone@poesidon.pspt.fi>
 *
 *	Changes:
 *              D.J. Barrow     :       Fixed bug where dev->refcnt gets set
 *              			to 2 if register_netdev gets called
 *              			before net_dev_init & also removed a
 *              			few lines of code in the process.
 *		Alan Cox	:	device private ioctl copies fields back.
 *		Alan Cox	:	Transmit queue code does relevant
 *					stunts to keep the queue safe.
 *		Alan Cox	:	Fixed double lock.
 *		Alan Cox	:	Fixed promisc NULL pointer trap
 *		????????	:	Support the full private ioctl range
 *		Alan Cox	:	Moved ioctl permission check into
 *					drivers
 *		Tim Kordas	:	SIOCADDMULTI/SIOCDELMULTI
 *		Alan Cox	:	100 backlog just doesn't cut it when
 *					you start doing multicast video 8)
 *		Alan Cox	:	Rewrote net_bh and list manager.
 *		Alan Cox	: 	Fix ETH_P_ALL echoback lengths.
 *		Alan Cox	:	Took out transmit every packet pass
 *					Saved a few bytes in the ioctl handler
 *		Alan Cox	:	Network driver sets packet type before
 *					calling netif_rx. Saves a function
 *					call a packet.
 *		Alan Cox	:	Hashed net_bh()
 *		Richard Kooijman:	Timestamp fixes.
 *		Alan Cox	:	Wrong field in SIOCGIFDSTADDR
 *		Alan Cox	:	Device lock protection.
 *		Alan Cox	: 	Fixed nasty side effect of device close
 *					changes.
 *		Rudi Cilibrasi	:	Pass the right thing to
 *					set_mac_address()
 *		Dave Miller	:	32bit quantity for the device lock to
 *					make it work out on a Sparc.
 *		Bjorn Ekwall	:	Added KERNELD hack.
 *		Alan Cox	:	Cleaned up the backlog initialise.
 *		Craig Metz	:	SIOCGIFCONF fix if space for under
 *					1 device.
 *	    Thomas Bogendoerfer :	Return ENODEV for dev_open, if there
 *					is no device open function.
 *		Andi Kleen	:	Fix error reporting for SIOCGIFCONF
 *	    Michael Chastain	:	Fix signed/unsigned for SIOCGIFCONF
 *		Cyrus Durgin	:	Cleaned for KMOD
 *		Adam Sulmicki   :	Bug Fix : Network Device Unload
 *					A network device unload needs to purge
 *					the backlog queue.
 *	Paul Rusty Russell	:	SIOCSIFNAME
 *              Pekka Riikonen  :	Netdev boot-time settings code
 *              Andrew Morton   :       Make unregister_netdevice wait
 *              			indefinitely on dev->refcnt
 * 		J Hadi Salim	:	- Backlog queue sampling
 *				        - netif_rx() feedback
 */
//ÍøÂçÉè±¸×¢²á¡¢ÊäÈë¡¢Êä³öµÈ½Ó¿ÚÔÚ¸Ã.cÀïÃæ
#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/bitops.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/if_bridge.h>
#include <linux/if_macvlan.h>
#include <net/dst.h>
#include <net/pkt_sched.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/module.h>
#include <linux/netpoll.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <net/wext.h>
#include <net/iw_handler.h>
#include <asm/current.h>
#include <linux/audit.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <trace/events/napi.h>
#include <linux/pci.h>

#include "net-sysfs.h"

/* Instead of increasing this, you should create a hash table. */
#define MAX_GRO_SKBS 8

/* This should be increased if a protocol with a bigger head is added. */
#define GRO_MAX_HEAD (MAX_HEADER + 128)

/*
 *	The list of packet types we will receive (as opposed to discard)
 *	and the routines to invoke.
 *
 *	Why 16. Because with 16 the only overlap we get on a hash of the
 *	low nibble of the protocol value is RARP/SNAP/X.25.
 *
 *      NOTE:  That is no longer true with the addition of VLAN tags.  Not
 *             sure which should go first, but I bet it won't make much
 *             difference if we are running VLANs.  The good news is that
 *             this protocol won't be in the list unless compiled in, so
 *             the average user (w/out VLANs) will not be adversely affected.
 *             --BLG
 *
 *		0800	IP
 *		8100    802.1Q VLAN
 *		0001	802.3
 *		0002	AX.25
 *		0004	802.2
 *		8035	RARP
 *		0005	SNAP
 *		0805	X.25
 *		0806	ARP
 *		8137	IPX
 *		0009	Localtalk
 *		86DD	IPv6
 */

#define PTYPE_HASH_SIZE	(16)
#define PTYPE_HASH_MASK	(PTYPE_HASH_SIZE - 1)

static DEFINE_SPINLOCK(ptype_lock);

/*
ËÑÒ»ÏÂÄÚºËÔ´´úÂë£¬¶ş²ãĞ­Òé»¹ÕæÊÇ¶à¡£¡£¡£
drivers/net/wan/hdlc.c: dev_add_pack(&hdlc_packet_type);  //ETH_P_HDLC    hdlc_rcv
drivers/net/wan/lapbether.c:
            dev_add_pack(&lapbeth_packet_type);         //ETH_P_DEC       lapbeth_rcv
drivers/net/wan/syncppp.c:
            dev_add_pack(&sppp_packet_type);            //ETH_P_WAN_PPP   sppp_rcv
drivers/net/bonding/bond_alb.c:  dev_add_pack(pk_type); //ETH_P_ARP       rlb_arp_recv
drivers/net/bonding/bond_main.c:dev_add_pack(pk_type);  //PKT_TYPE_LACPDU bond_3ad_lacpdu_recv
drivers/net/bonding/bond_main.c:dev_add_pack(pt);       //ETH_P_ARP       bond_arp_rcv
drivers/net/pppoe.c: dev_add_pack(&pppoes_ptype);       //ETH_P_PPP_SES   pppoe_rcv
drivers/net/pppoe.c: dev_add_pack(&pppoed_ptype);       //ETH_P_PPP_DISC  pppoe_disc_rcv
drivers/net/hamradio/bpqether.c:
                    dev_add_pack(&bpq_packet_type);     //ETH_P_BPQ       bpq_rcv
net/ipv4/af_inet.c:  dev_add_pack(&ip_packet_type);     //ETH_P_IP       ip_rcv
net/ipv4/arp.c:    dev_add_pack(&arp_packet_type);      //ETH_P_ARP       arp_rcv
net/ipv4/ipconfig.c:  dev_add_pack(&rarp_packet_type);  //ETH_P_RARP      ic_rarp_recv
net/ipv4/ipconfig.c:  dev_add_pack(&bootp_packet_type); //ETH_P_IP        ic_bootp_recv
net/llc/llc_core.c: dev_add_pack(&llc_packet_type);     //ETH_P_802_2     llc_rcv
net/llc/llc_core.c: dev_add_pack(&llc_tr_packet_type);  //ETH_P_TR_802_2  llc_rcv
net/x25/af_x25.c:  dev_add_pack(&x25_packet_type);    //ETH_P_X25      x25_lapb_receive_frame
net/8021q/vlan.c:  dev_add_pack(&vlan_packet_type);     //ETH_P_8021Q     vlan_skb_recv

ÕâĞ©²»Í¬Ğ­ÒéµÄpacket_type£¬ÓĞĞ©ÊÇlinuxÏµÍ³Æô¶¯Ê±¹ÒÉÏÈ¥µÄ
±ÈÈç´¦ÀíipĞ­ÒéµÄpakcet_type£¬¾ÍÊÇÔÚ inet_init()Ê±¹ÒÉÏÈ¥µÄ
»¹ÓĞĞ©Çı¶¯Ä£¿é¼ÓÔØµÄÊ±ºò²Å¼ÓÉÏÈ¥µÄ
*///Íø¿¨Çı¶¯×îºóµ÷ÓÃnetif_receive_skb£¬´Ó¶øÖ´ĞĞfuncº¯Êı 
//ÍøÂç×¥°ütcpdumpÒ²ÔÚ¶ş²ãÊµÏÖ£¬²Î¿¼http://blog.csdn.net/jw212/article/details/6738497

//¸³ÖµµÄµØ·½ÔÚdev_add_pack
static struct list_head ptype_base[PTYPE_HASH_SIZE];//__read_mostly;//ÕâĞ©´¦Àíº¯ÊıÓÃÀ´´¦Àí½ÓÊÕµ½µÄ²»Í¬Ğ­Òé×åµÄ±¨ÎÄ  

/*
»ìÔÓÄ£Ê½£¨Promiscuous Mode£©ÊÇÖ¸Ò»Ì¨»úÆ÷ÄÜ¹»½ÓÊÕËùÓĞ¾­¹ıËüµÄÊı¾İÁ÷£¬¶ø²»ÂÛÆäÄ¿µÄµØÖ·ÊÇ·ñÊÇËû¡£ÊÇÏà¶ÔÓÚÍ¨³£Ä£Ê½£¨ÓÖ³Æ¡°·Ç»ìÔÓÄ£Ê½¡±£©¶øÑÔµÄ¡£
Õâ±»ÍøÂç¹ÜÀíÔ±Ê¹ÓÃÀ´Õï¶ÏÍøÂçÎÊÌâ£¬µ«ÊÇÒ²±»ÎŞÈÏÖ¤µÄÏëÍµÌıÍøÂçÍ¨ĞÅ£¨Æä¿ÉÄÜ°üÀ¨ÃÜÂëºÍÆäËüÃô¸ĞµÄĞÅÏ¢£©µÄÈËÀûÓÃ¡£Ò»¸ö·ÇÂ·ÓÉÑ¡Ôñ½ÚµãÔÚ»ìÔÓÄ£Ê½ÏÂ
Ò»°ã½öÄÜ¹»ÔÚÏàÍ¬µÄ³åÍ»Óò£¨¶ÔÒÔÌ«ÍøºÍÎŞÏß¾ÖÓòÍø£©ÄÚ¼à¿ØÍ¨ĞÅµ½ºÍÀ´×ÔÆäËü½Úµã»ò»·£¨¶ÔÁîÅÆ»·»òFDDI£©£¬ÆäÊÇÎªÊ²Ã´ÍøÂç½»»»±»ÓÃÓÚ¶Ô¿¹¶ñÒâµÄ»ìÔÓÄ£Ê½¡£¡¡¡¡»ìÔÓÄ£Ê½¾ÍÊÇ½ÓÊÕËùÓĞ¾­¹ıÍø¿¨µÄÊı¾İ°ü£¬°üÀ¨²»ÊÇ·¢¸ø±¾»úµÄ°ü¡£Ä¬ÈÏÇé¿öÏÂÍø¿¨Ö»°Ñ·¢¸ø±¾»úµÄ°ü£¨°üÀ¨¹ã²¥°ü£©´«µİ¸øÉÏ²ã³ÌĞò£¬ÆäËüµÄ°üÒ»ÂÉ¶ªÆú¡£
¼òµ¥µÄ½²,»ìÔÓÄ£Ê½¾ÍÊÇÖ¸Íø¿¨ÄÜ½ÓÊÜËùÓĞÍ¨¹ıËüµÄÊı¾İÁ÷£¬²»¹ÜÊÇÊ²Ã´¸ñÊ½£¬Ê²Ã´µØÖ·µÄ¡£ÊÂÊµÉÏ£¬¼ÆËã»úÊÕµ½Êı¾İ°üºó£¬ÓÉÍøÂç²ã½øĞĞÅĞ¶Ï£¬È·¶¨ÊÇµİ½»ÉÏ²ã£¨´«Êä²ã£©£¬»¹ÊÇ¶ªÆú£¬»¹ÊÇµİ½»ÏÂ²ã£¨Êı¾İÁ´Â·²ã¡¢MAC×Ó²ã£©×ª·¢¡£¡¡¡¡Í¨³£ÔÚĞèÒªÓÃµ½×¥°ü¹¤¾ß£¬ÀıÈçethereal¡¢snifferÊ±£¬ĞèÒª°ÑÍø¿¨ÖÃÓÚ»ìÔÓÄ£Ê½£¬ĞèÒªÓÃµ½Èí¼şWinpcap¡£winpcapÊÇwindowsÆ½Ì¨ÏÂÒ»¸öÃâ·Ñ£¬¹«¹²µÄÍøÂç·ÃÎÊÏµÍ³¡£¿ª·¢winpcapÕâ¸öÏîÄ¿µÄÄ¿µÄÔÚÓÚÎªwin32Ó¦ÓÃ³ÌĞòÌá¹©·ÃÎÊÍøÂçµ×²ãµÄÄÜÁ¦¡£
po->prot_hook.func = packet_rcv;

if (sock->type == SOCK_PACKET)
	po->prot_hook.func = packet_rcv_spkt;

ETH_P_ALLµÄ×¢²áÔÚpacket_createÖĞ£¬¸Ãº¯ÊıÊÇÍ¨¹ıÓ¦ÓÃ²ãµÄº¯ÊınSock == socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))ÏµÍ³µ÷ÓÃµÄ¡£ptype_all Á´£¬ÕâĞ©Îª×¢²áµ½ÄÚºËµÄÒ»Ğ© sniffer£¬½«ÉÏ´«¸øÕâĞ©sniffer£¬ÁíÒ»¸ö¾ÍÊÇ±éÀú ptype_base£¬Õâ¸ö¾ÍÊÇ¾ßÌåµÄĞ­ÒéÀàĞÍ
*/ //½ÓÊÕ¼û__netif_receive_skb£¬·¢ËÍ¼ûdev_queue_xmit_nit
static struct list_head ptype_all;// __read_mostly;	/* Taps */ //ÔÚnet_dev_initÖĞ³õÊ¼»¯

/*
 * The @dev_base_head list is protected by @dev_base_lock and the rtnl
 * semaphore.
 *
 * Pure readers hold dev_base_lock for reading, or rcu_read_lock()
 *
 * Writers must hold the rtnl semaphore while they loop through the
 * dev_base_head list, and hold dev_base_lock for writing when they do the
 * actual updates.  This allows pure readers to access the list even
 * while a writer is preparing to update it.
 *
 * To put it another way, dev_base_lock is held for writing only to
 * protect against pure readers; the rtnl semaphore provides the
 * protection against other writers.
 *
 * See, for example usages, register_netdevice() and
 * unregister_netdevice(), which must be called with the rtnl
 * semaphore held.
 */
DEFINE_RWLOCK(dev_base_lock);
EXPORT_SYMBOL(dev_base_lock);

static inline struct hlist_head *dev_name_hash(struct net *net, const char *name)
{
	unsigned hash = full_name_hash(name, strnlen(name, IFNAMSIZ));
	return &net->dev_name_head[hash_32(hash, NETDEV_HASHBITS)];
}

static inline struct hlist_head *dev_index_hash(struct net *net, int ifindex)
{
	return &net->dev_index_head[ifindex & (NETDEV_HASHENTRIES - 1)];
}

static inline void rps_lock(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	spin_lock(&sd->input_pkt_queue.lock);
#endif
}

static inline void rps_unlock(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	spin_unlock(&sd->input_pkt_queue.lock);
#endif
}

/* Device list insertion */
static int list_netdevice(struct net_device *dev)
{
	struct net *net = dev_net(dev);

	ASSERT_RTNL();

	write_lock_bh(&dev_base_lock);
	list_add_tail_rcu(&dev->dev_list, &net->dev_base_head);
	hlist_add_head_rcu(&dev->name_hlist, dev_name_hash(net, dev->name));
	hlist_add_head_rcu(&dev->index_hlist,
			   dev_index_hash(net, dev->ifindex));
	write_unlock_bh(&dev_base_lock);
	return 0;
}

/* Device list removal
 * caller must respect a RCU grace period before freeing/reusing dev
 */

/*
  * ½«´ı×¢ÏúµÄÍøÂçÉè±¸ÊµÀı´ÓÈ«¾Östruct netµÄ
  * Á´±ídev_base_head¼°dev_name_head¡¢dev_index_head
  * É¢ÁĞ±íÖĞÒÆ³ı¡£ÒÆ³ıºó²»ÄÜ×èÖ¹
  * ÄÚºË×ÓÏµÍ³Ê¹ÓÃ¸ÃÉè±¸£¬ËûÃÇÈÔÈ»
  * ÓµÓĞÖ¸Ïò¸Ãnet_device½á¹¹ÊµÀıµÄÖ¸Õë£¬
  * Ö»ÓĞµ±ÒıÓÃ¼ÆÊıÎª0Ê±²Å»áÕæÕıÊÍ·Å
  * ÊµÀı¡£
  */
static void unlist_netdevice(struct net_device *dev)
{
	ASSERT_RTNL();

	/* Unlink dev from the device chain */
	write_lock_bh(&dev_base_lock);
	list_del_rcu(&dev->dev_list);
	hlist_del_rcu(&dev->name_hlist);
	hlist_del_rcu(&dev->index_hlist);
	write_unlock_bh(&dev_base_lock);
}

/*
 *	Our notifier list
 */
 //ÈçÍ¼ 1ÖĞËùÊ¾£¬LinuxµÄÍøÂç×ÓÏµÍ³Ò»¹²ÓĞ3¸öÍ¨ÖªÁ´£º±íÊ¾ipv4µØÖ··¢Éú±ä»¯Ê±µÄinetaddr_chain£»±íÊ¾ipv6µØÖ··¢Éú±ä»¯µÄinet6addr_chain£»»¹ÓĞ±íÊ¾Éè±¸×¢²á¡¢×´Ì¬±ä»¯µÄnetdev_chain¡£
//RAW_NOTIFIER_HEAD(netdev_chain);Ô­Ê¼Í¨ÖªÁ´£¨ Raw notifierchains £©£º¶ÔÍ¨ÖªÁ´ÔªËØµÄ»Øµ÷º¯ÊıÃ»ÓĞÈÎºÎÏŞÖÆ£¬ËùÓĞËøºÍ±£»¤»úÖÆ¶¼ÓÉµ÷ÓÃÕßÎ¬»¤¡£¶ÔÓ¦µÄÁ´±íÍ·£º
//ÍøÂç×ÓÏµÍ³¾ÍÊÇ¸ÃÀàĞÍ£¬Í¨¹ıÒÔÏÂºêÊµÏÖheadµÄ³õÊ¼»¯
//netdev_chainÎªÔ­Ê¼rawÍ¨ÖªÁ¬£¬Í¨ÖªÊÂ¼şº¯ÊıÎª__raw_notifier_call_chain
//static RAW_NOTIFIER_HEAD(netdev_chain);
/*
LinuxÄÚºËÖĞ¸÷¸ö×ÓÏµÍ³Ïà»¥ÒÀÀµ£¬µ±ÆäÖĞÄ³¸ö×ÓÏµÍ³×´Ì¬·¢Éú¸Ä±äÊ±£¬¾Í±ØĞëÊ¹ÓÃÒ»¶¨µÄ»úÖÆ¸æÖªÊ¹ÓÃÆä·şÎñµÄÆäËû×ÓÏµÍ³£¬ÒÔ±ãÆäËû×ÓÏµÍ³²ÉÈ¡ÏàÓ¦µÄ´ëÊ©¡£
ÎªÂú×ãÕâÑùµÄĞèÇó£¬ÄÚºËÊµÏÖÁËÊÂ¼şÍ¨ÖªÁ´»úÖÆ£¨notificationchain£©¡£
*/
/*
Ô­×ÓÍ¨ÖªÁ´£¨ Atomic notifier chains £©£ºÍ¨ÖªÁ´ÔªËØµÄ»Øµ÷º¯Êı£¨µ±ÊÂ¼ş·¢ÉúÊ±ÒªÖ´ĞĞµÄº¯Êı£©ÔÚÖĞ¶Ï»òÔ­×Ó²Ù×÷ÉÏÏÂÎÄÖĞÔËĞĞ£¬²»ÔÊĞí×èÈû¡£¶ÔÓ¦µÄÁ´±íÍ·½á¹¹£º
¿É×èÈûÍ¨ÖªÁ´£¨ Blocking notifier chains £©£ºÍ¨ÖªÁ´ÔªËØµÄ»Øµ÷º¯ÊıÔÚ½ø³ÌÉÏÏÂÎÄÖĞÔËĞĞ£¬ÔÊĞí×èÈû¡£¶ÔÓ¦µÄÁ´±íÍ·£º
Ô­Ê¼Í¨ÖªÁ´£¨ Raw notifierchains £©£º¶ÔÍ¨ÖªÁ´ÔªËØµÄ»Øµ÷º¯ÊıÃ»ÓĞÈÎºÎÏŞÖÆ£¬ËùÓĞËøºÍ±£»¤»úÖÆ¶¼ÓÉµ÷ÓÃÕßÎ¬»¤¡£¶ÔÓ¦µÄÁ´±íÍ·£º
SRCU Í¨ÖªÁ´£¨ SRCU notifier chains £©£º¿É×èÈûÍ¨ÖªÁ´µÄÒ»ÖÖ±äÌå¡£¶ÔÓ¦µÄÁ´±íÍ·£º

LinuxµÄÍøÂç×ÓÏµÍ³Ò»¹²ÓĞ3¸öÍ¨ÖªÁ´£º±íÊ¾ipv4µØÖ··¢Éú±ä»¯Ê±µÄinetaddr_chain£»±íÊ¾ipv6µØÖ··¢Éú±ä»¯µÄinet6addr_chain£»»¹ÓĞ±íÊ¾Éè±¸×¢²á¡¢
×´Ì¬±ä»¯µÄnetdev_chain¡£
*/

struct raw_notifier_head netdev_chain =	RAW_NOTIFIER_INIT(netdev_chain) //ÔÚregister_netdevice_notifierÖĞ

/*
 *	Device drivers call our routines to queue packets here. We empty the
 *	queue in the local softnet handler.
 */

DEFINE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);
EXPORT_PER_CPU_SYMBOL(softnet_data);

#ifdef CONFIG_LOCKDEP
/*
 * register_netdevice() inits txq->_xmit_lock and sets lockdep class
 * according to dev->type
 */
static const unsigned short netdev_lock_type[] =
	{ARPHRD_NETROM, ARPHRD_ETHER, ARPHRD_EETHER, ARPHRD_AX25,
	 ARPHRD_PRONET, ARPHRD_CHAOS, ARPHRD_IEEE802, ARPHRD_ARCNET,
	 ARPHRD_APPLETLK, ARPHRD_DLCI, ARPHRD_ATM, ARPHRD_METRICOM,
	 ARPHRD_IEEE1394, ARPHRD_EUI64, ARPHRD_INFINIBAND, ARPHRD_SLIP,
	 ARPHRD_CSLIP, ARPHRD_SLIP6, ARPHRD_CSLIP6, ARPHRD_RSRVD,
	 ARPHRD_ADAPT, ARPHRD_ROSE, ARPHRD_X25, ARPHRD_HWX25,
	 ARPHRD_PPP, ARPHRD_CISCO, ARPHRD_LAPB, ARPHRD_DDCMP,
	 ARPHRD_RAWHDLC, ARPHRD_TUNNEL, ARPHRD_TUNNEL6, ARPHRD_FRAD,
	 ARPHRD_SKIP, ARPHRD_LOOPBACK, ARPHRD_LOCALTLK, ARPHRD_FDDI,
	 ARPHRD_BIF, ARPHRD_SIT, ARPHRD_IPDDP, ARPHRD_IPGRE,
	 ARPHRD_PIMREG, ARPHRD_HIPPI, ARPHRD_ASH, ARPHRD_ECONET,
	 ARPHRD_IRDA, ARPHRD_FCPP, ARPHRD_FCAL, ARPHRD_FCPL,
	 ARPHRD_FCFABRIC, ARPHRD_IEEE802_TR, ARPHRD_IEEE80211,
	 ARPHRD_IEEE80211_PRISM, ARPHRD_IEEE80211_RADIOTAP, ARPHRD_PHONET,
	 ARPHRD_PHONET_PIPE, ARPHRD_IEEE802154,
	 ARPHRD_VOID, ARPHRD_NONE};

static const char *const netdev_lock_name[] =
	{"_xmit_NETROM", "_xmit_ETHER", "_xmit_EETHER", "_xmit_AX25",
	 "_xmit_PRONET", "_xmit_CHAOS", "_xmit_IEEE802", "_xmit_ARCNET",
	 "_xmit_APPLETLK", "_xmit_DLCI", "_xmit_ATM", "_xmit_METRICOM",
	 "_xmit_IEEE1394", "_xmit_EUI64", "_xmit_INFINIBAND", "_xmit_SLIP",
	 "_xmit_CSLIP", "_xmit_SLIP6", "_xmit_CSLIP6", "_xmit_RSRVD",
	 "_xmit_ADAPT", "_xmit_ROSE", "_xmit_X25", "_xmit_HWX25",
	 "_xmit_PPP", "_xmit_CISCO", "_xmit_LAPB", "_xmit_DDCMP",
	 "_xmit_RAWHDLC", "_xmit_TUNNEL", "_xmit_TUNNEL6", "_xmit_FRAD",
	 "_xmit_SKIP", "_xmit_LOOPBACK", "_xmit_LOCALTLK", "_xmit_FDDI",
	 "_xmit_BIF", "_xmit_SIT", "_xmit_IPDDP", "_xmit_IPGRE",
	 "_xmit_PIMREG", "_xmit_HIPPI", "_xmit_ASH", "_xmit_ECONET",
	 "_xmit_IRDA", "_xmit_FCPP", "_xmit_FCAL", "_xmit_FCPL",
	 "_xmit_FCFABRIC", "_xmit_IEEE802_TR", "_xmit_IEEE80211",
	 "_xmit_IEEE80211_PRISM", "_xmit_IEEE80211_RADIOTAP", "_xmit_PHONET",
	 "_xmit_PHONET_PIPE", "_xmit_IEEE802154",
	 "_xmit_VOID", "_xmit_NONE"};

static struct lock_class_key netdev_xmit_lock_key[ARRAY_SIZE(netdev_lock_type)];
static struct lock_class_key netdev_addr_lock_key[ARRAY_SIZE(netdev_lock_type)];

static inline unsigned short netdev_lock_pos(unsigned short dev_type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(netdev_lock_type); i++)
		if (netdev_lock_type[i] == dev_type)
			return i;
	/* the last key is used by default */
	return ARRAY_SIZE(netdev_lock_type) - 1;
}

static inline void netdev_set_xmit_lockdep_class(spinlock_t *lock,
						 unsigned short dev_type)
{
	int i;

	i = netdev_lock_pos(dev_type);
	lockdep_set_class_and_name(lock, &netdev_xmit_lock_key[i],
				   netdev_lock_name[i]);
}

static inline void netdev_set_addr_lockdep_class(struct net_device *dev)
{
	int i;

	i = netdev_lock_pos(dev->type);
	lockdep_set_class_and_name(&dev->addr_list_lock,
				   &netdev_addr_lock_key[i],
				   netdev_lock_name[i]);
}
#else
static inline void netdev_set_xmit_lockdep_class(spinlock_t *lock,
						 unsigned short dev_type)
{
}
static inline void netdev_set_addr_lockdep_class(struct net_device *dev)
{
}
#endif

/*******************************************************************************

		Protocol management and registration routines

*******************************************************************************/

/*
 *	Add a protocol ID to the list. Now that the input handler is
 *	smarter we can dispense with all the messy stuff that used to be
 *	here.
 *
 *	BEWARE!!! Protocol handlers, mangling input packets,
 *	MUST BE last in hash buckets and checking protocol handlers
 *	MUST start from promiscuous ptype_all chain in net_bh.
 *	It is true now, do not change it.
 *	Explanation follows: if protocol handler, mangling packet, will
 *	be the first on list, it is not able to sense, that packet
 *	is cloned and should be copied-on-write, so that it will
 *	change it and subsequent readers will get broken packet.
 *							--ANK (980803)
 */

/**
 *	dev_add_pack - add packet handler
 *	@pt: packet type declaration
 *
 *	Add a protocol handler to the networking stack. The passed &packet_type
 *	is linked into kernel lists and may not be freed until it has been
 *	removed from the kernel lists.
 *
 *	This call does not sleep therefore it can not
 *	guarantee all CPU's that are in middle of receiving packets
 *	will see the new packet type (until the next received packet).
 */
/*
ËÑÒ»ÏÂÄÚºËÔ´´úÂë£¬¶ş²ãĞ­Òé»¹ÕæÊÇ¶à¡£¡£¡£
drivers/net/wan/hdlc.c: dev_add_pack(&hdlc_packet_type);  //ETH_P_HDLC    hdlc_rcv
drivers/net/wan/lapbether.c:
            dev_add_pack(&lapbeth_packet_type);         //ETH_P_DEC       lapbeth_rcv
drivers/net/wan/syncppp.c:
            dev_add_pack(&sppp_packet_type);            //ETH_P_WAN_PPP   sppp_rcv
drivers/net/bonding/bond_alb.c:  dev_add_pack(pk_type); //ETH_P_ARP       rlb_arp_recv
drivers/net/bonding/bond_main.c:dev_add_pack(pk_type);  //PKT_TYPE_LACPDU bond_3ad_lacpdu_recv
drivers/net/bonding/bond_main.c:dev_add_pack(pt);       //ETH_P_ARP       bond_arp_rcv
drivers/net/pppoe.c: dev_add_pack(&pppoes_ptype);       //ETH_P_PPP_SES   pppoe_rcv
drivers/net/pppoe.c: dev_add_pack(&pppoed_ptype);       //ETH_P_PPP_DISC  pppoe_disc_rcv
drivers/net/hamradio/bpqether.c:
                    dev_add_pack(&bpq_packet_type);     //ETH_P_BPQ       bpq_rcv
net/ipv4/af_inet.c:  dev_add_pack(&ip_packet_type);     //ETH_P_IP       ip_rcv
net/ipv4/arp.c:    dev_add_pack(&arp_packet_type);      //ETH_P_ARP       arp_rcv
net/ipv4/ipconfig.c:  dev_add_pack(&rarp_packet_type);  //ETH_P_RARP      ic_rarp_recv
net/ipv4/ipconfig.c:  dev_add_pack(&bootp_packet_type); //ETH_P_IP        ic_bootp_recv
net/llc/llc_core.c: dev_add_pack(&llc_packet_type);     //ETH_P_802_2     llc_rcv
net/llc/llc_core.c: dev_add_pack(&llc_tr_packet_type);  //ETH_P_TR_802_2  llc_rcv
net/x25/af_x25.c:  dev_add_pack(&x25_packet_type);    //ETH_P_X25      x25_lapb_receive_frame
net/8021q/vlan.c:  dev_add_pack(&vlan_packet_type);     //ETH_P_8021Q     vlan_skb_recv

ÕâĞ©²»Í¬Ğ­ÒéµÄpacket_type£¬ÓĞĞ©ÊÇlinuxÏµÍ³Æô¶¯Ê±¹ÒÉÏÈ¥µÄ
±ÈÈç´¦ÀíipĞ­ÒéµÄpakcet_type£¬¾ÍÊÇÔÚ inet_init()Ê±¹ÒÉÏÈ¥µÄ
»¹ÓĞĞ©Çı¶¯Ä£¿é¼ÓÔØµÄÊ±ºò²Å¼ÓÉÏÈ¥µÄ
*///Íø¿¨Çı¶¯×îºóµ÷ÓÃnetif_receive_skb£¬´Ó¶øÖ´ĞĞfuncº¯Êı 
//ÍøÂç×¥°ütcpdumpÒ²ÔÚ¶ş²ãÊµÏÖ£¬²Î¿¼http://blog.csdn.net/jw212/article/details/6738497
/*
»ìÔÓÄ£Ê½£¨Promiscuous Mode£©ÊÇÖ¸Ò»Ì¨»úÆ÷ÄÜ¹»½ÓÊÕËùÓĞ¾­¹ıËüµÄÊı¾İÁ÷£¬¶ø²»ÂÛÆäÄ¿µÄµØÖ·ÊÇ·ñÊÇËû¡£ÊÇÏà¶ÔÓÚÍ¨³£Ä£Ê½£¨ÓÖ³Æ¡°·Ç»ìÔÓÄ£Ê½¡±£©¶øÑÔµÄ¡£
Õâ±»ÍøÂç¹ÜÀíÔ±Ê¹ÓÃÀ´Õï¶ÏÍøÂçÎÊÌâ£¬µ«ÊÇÒ²±»ÎŞÈÏÖ¤µÄÏëÍµÌıÍøÂçÍ¨ĞÅ£¨Æä¿ÉÄÜ°üÀ¨ÃÜÂëºÍÆäËüÃô¸ĞµÄĞÅÏ¢£©µÄÈËÀûÓÃ¡£Ò»¸ö·ÇÂ·ÓÉÑ¡Ôñ½ÚµãÔÚ»ìÔÓÄ£Ê½ÏÂ
Ò»°ã½öÄÜ¹»ÔÚÏàÍ¬µÄ³åÍ»Óò£¨¶ÔÒÔÌ«ÍøºÍÎŞÏß¾ÖÓòÍø£©ÄÚ¼à¿ØÍ¨ĞÅµ½ºÍÀ´×ÔÆäËü½Úµã»ò»·£¨¶ÔÁîÅÆ»·»òFDDI£©£¬ÆäÊÇÎªÊ²Ã´ÍøÂç½»»»±»ÓÃÓÚ¶Ô¿¹¶ñÒâµÄ»ìÔÓÄ£Ê½¡£¡¡¡¡»ìÔÓÄ£Ê½¾ÍÊÇ½ÓÊÕËùÓĞ¾­¹ıÍø¿¨µÄÊı¾İ°ü£¬°üÀ¨²»ÊÇ·¢¸ø±¾»úµÄ°ü¡£Ä¬ÈÏÇé¿öÏÂÍø¿¨Ö»°Ñ·¢¸ø±¾»úµÄ°ü£¨°üÀ¨¹ã²¥°ü£©´«µİ¸øÉÏ²ã³ÌĞò£¬ÆäËüµÄ°üÒ»ÂÉ¶ªÆú¡£¼òµ¥µÄ½²,»ìÔÓÄ£Ê½¾ÍÊÇÖ¸Íø¿¨ÄÜ½ÓÊÜËùÓĞÍ¨¹ıËüµÄÊı¾İÁ÷£¬²»¹ÜÊÇÊ²Ã´¸ñÊ½£¬Ê²Ã´µØÖ·µÄ¡£ÊÂÊµÉÏ£¬¼ÆËã»úÊÕµ½Êı¾İ°üºó£¬ÓÉÍøÂç²ã½øĞĞÅĞ¶Ï£¬È·¶¨ÊÇµİ½»ÉÏ²ã£¨´«Êä²ã£©£¬»¹ÊÇ¶ªÆú£¬»¹ÊÇµİ½»ÏÂ²ã£¨Êı¾İÁ´Â·²ã¡¢MAC×Ó²ã£©×ª·¢¡£¡¡¡¡Í¨³£ÔÚĞèÒªÓÃµ½×¥°ü¹¤¾ß£¬ÀıÈçethereal¡¢snifferÊ±£¬ĞèÒª°ÑÍø¿¨ÖÃÓÚ»ìÔÓÄ£Ê½£¬ĞèÒªÓÃµ½Èí¼şWinpcap¡£winpcapÊÇwindowsÆ½Ì¨ÏÂÒ»¸öÃâ·Ñ£¬¹«¹²µÄÍøÂç·ÃÎÊÏµÍ³¡£¿ª·¢winpcapÕâ¸öÏîÄ¿µÄÄ¿µÄÔÚÓÚÎªwin32Ó¦ÓÃ³ÌĞòÌá¹©·ÃÎÊÍøÂçµ×²ãµÄÄÜÁ¦¡£

ETH_P_ALLµÄ×¢²áÔÚpacket_createÖĞ£¬¸Ãº¯ÊıÊÇÍ¨¹ıÓ¦ÓÃ²ãµÄº¯ÊınSock == socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))ÏµÍ³µ÷ÓÃµÄ¡£ptype_all Á´£¬ÕâĞ©Îª×¢²áµ½ÄÚºËµÄÒ»Ğ© sniffer£¬½«ÉÏ´«¸øÕâĞ©sniffer£¬ÁíÒ»¸ö¾ÍÊÇ±éÀú ptype_base£¬Õâ¸ö¾ÍÊÇ¾ßÌåµÄĞ­ÒéÀàĞÍ
*/
void dev_add_pack(struct packet_type *pt)
{
	int hash;

	spin_lock_bh(&ptype_lock);
	if (pt->type == htons(ETH_P_ALL))
		list_add_rcu(&pt->list, &ptype_all);
	else {
		hash = ntohs(pt->type) & PTYPE_HASH_MASK;
		list_add_rcu(&pt->list, &ptype_base[hash]);
	}
	spin_unlock_bh(&ptype_lock);
}
EXPORT_SYMBOL(dev_add_pack);

/**
 *	__dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns.
 *
 *      The packet type might still be in use by receivers
 *	and must not be freed until after all the CPU's have gone
 *	through a quiescent state.
 */
void __dev_remove_pack(struct packet_type *pt)
{
	struct list_head *head;
	struct packet_type *pt1;

	spin_lock_bh(&ptype_lock);

	if (pt->type == htons(ETH_P_ALL))
		head = &ptype_all;
	else
		head = &ptype_base[ntohs(pt->type) & PTYPE_HASH_MASK];

	list_for_each_entry(pt1, head, list) {
		if (pt == pt1) {
			list_del_rcu(&pt->list);
			goto out;
		}
	}

	printk(KERN_WARNING "dev_remove_pack: %p not found.\n", pt);
out:
	spin_unlock_bh(&ptype_lock);
}
EXPORT_SYMBOL(__dev_remove_pack);

/**
 *	dev_remove_pack	 - remove packet handler
 *	@pt: packet type declaration
 *
 *	Remove a protocol handler that was previously added to the kernel
 *	protocol handlers by dev_add_pack(). The passed &packet_type is removed
 *	from the kernel lists and can be freed or reused once this function
 *	returns.
 *
 *	This call sleeps to guarantee that no CPU is looking at the packet
 *	type after return.
 */
void dev_remove_pack(struct packet_type *pt)
{
	__dev_remove_pack(pt);

	synchronize_net();
}
EXPORT_SYMBOL(dev_remove_pack);

/******************************************************************************

		      Device Boot-time Settings Routines

*******************************************************************************/

/* Boot time configuration table */
static struct netdev_boot_setup dev_boot_setup[NETDEV_BOOT_SETUP_MAX];

/**
 *	netdev_boot_setup_add	- add new setup entry
 *	@name: name of the device
 *	@map: configured settings for the device
 *
 *	Adds new setup entry to the dev_boot_setup list.  The function
 *	returns 0 on error and 1 on success.  This is a generic routine to
 *	all netdevices.
 */
static int netdev_boot_setup_add(char *name, struct ifmap *map)
{
	struct netdev_boot_setup *s;
	int i;

	s = dev_boot_setup;
	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] == '\0' || s[i].name[0] == ' ') {
			memset(s[i].name, 0, sizeof(s[i].name));
			strlcpy(s[i].name, name, IFNAMSIZ);
			memcpy(&s[i].map, map, sizeof(s[i].map));
			break;
		}
	}

	return i >= NETDEV_BOOT_SETUP_MAX ? 0 : 1;
}

/**
 *	netdev_boot_setup_check	- check boot time settings
 *	@dev: the netdevice
 *
 * 	Check boot time settings for the device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found, 1 if they are.
 */
int netdev_boot_setup_check(struct net_device *dev)
{
	struct netdev_boot_setup *s = dev_boot_setup;
	int i;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++) {
		if (s[i].name[0] != '\0' && s[i].name[0] != ' ' &&
		    !strcmp(dev->name, s[i].name)) {
			dev->irq 	= s[i].map.irq;
			dev->base_addr 	= s[i].map.base_addr;
			dev->mem_start 	= s[i].map.mem_start;
			dev->mem_end 	= s[i].map.mem_end;
			return 1;
		}
	}
	return 0;
}
EXPORT_SYMBOL(netdev_boot_setup_check);


/**
 *	netdev_boot_base	- get address from boot time settings
 *	@prefix: prefix for network device
 *	@unit: id for network device
 *
 * 	Check boot time settings for the base address of device.
 *	The found settings are set for the device to be used
 *	later in the device probing.
 *	Returns 0 if no settings found.
 */
unsigned long netdev_boot_base(const char *prefix, int unit)
{
	const struct netdev_boot_setup *s = dev_boot_setup;
	char name[IFNAMSIZ];
	int i;

	sprintf(name, "%s%d", prefix, unit);

	/*
	 * If device already registered then return base of 1
	 * to indicate not to probe for this interface
	 */
	if (__dev_get_by_name(&init_net, name))
		return 1;

	for (i = 0; i < NETDEV_BOOT_SETUP_MAX; i++)
		if (!strcmp(name, s[i].name))
			return s[i].map.base_addr;
	return 0;
}

/*
 * Saves at boot time configured settings for any netdevice.
 */
int __init netdev_boot_setup(char *str)
{
	int ints[5];
	struct ifmap map;

	str = get_options(str, ARRAY_SIZE(ints), ints);
	if (!str || !*str)
		return 0;

	/* Save settings */
	memset(&map, 0, sizeof(map));
	if (ints[0] > 0)
		map.irq = ints[1];
	if (ints[0] > 1)
		map.base_addr = ints[2];
	if (ints[0] > 2)
		map.mem_start = ints[3];
	if (ints[0] > 3)
		map.mem_end = ints[4];

	/* Add new entry to the list */
	return netdev_boot_setup_add(str, &map);
}

__setup("netdev=", netdev_boot_setup);

/*******************************************************************************

			    Device Interface Subroutines

*******************************************************************************/

/**
 *	__dev_get_by_name	- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name. Must be called under RTNL semaphore
 *	or @dev_base_lock. If the name is found a pointer to the device
 *	is returned. If the name is not found then %NULL is returned. The
 *	reference counters are not incremented so the caller must be
 *	careful with locks.
 */

struct net_device *__dev_get_by_name(struct net *net, const char *name)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_name_hash(net, name);

	hlist_for_each_entry(dev, p, head, name_hlist)
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_get_by_name);

/**
 *	dev_get_by_name_rcu	- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name.
 *	If the name is found a pointer to the device is returned.
 * 	If the name is not found then %NULL is returned.
 *	The reference counters are not incremented so the caller must be
 *	careful with locks. The caller must hold RCU lock.
 */

struct net_device *dev_get_by_name_rcu(struct net *net, const char *name)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_name_hash(net, name);

	hlist_for_each_entry_rcu(dev, p, head, name_hlist)
		if (!strncmp(dev->name, name, IFNAMSIZ))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_get_by_name_rcu);

/**
 *	dev_get_by_name		- find a device by its name
 *	@net: the applicable net namespace
 *	@name: name to find
 *
 *	Find an interface by name. This can be called from any
 *	context and does its own locking. The returned handle has
 *	the usage count incremented and the caller must use dev_put() to
 *	release it when it is no longer needed. %NULL is returned if no
 *	matching device is found.
 */

struct net_device *dev_get_by_name(struct net *net, const char *name)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(net, name);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();
	return dev;
}
EXPORT_SYMBOL(dev_get_by_name);

/**
 *	__dev_get_by_index - find a device by its ifindex
 *	@net: the applicable net namespace
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold either the RTNL semaphore
 *	or @dev_base_lock.
 */

struct net_device *__dev_get_by_index(struct net *net, int ifindex)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_index_hash(net, ifindex);

	hlist_for_each_entry(dev, p, head, index_hlist)
		if (dev->ifindex == ifindex)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_get_by_index);

/**
 *	dev_get_by_index_rcu - find a device by its ifindex
 *	@net: the applicable net namespace
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns %NULL if the device
 *	is not found or a pointer to the device. The device has not
 *	had its reference counter increased so the caller must be careful
 *	about locking. The caller must hold RCU lock.
 */

struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex)
{
	struct hlist_node *p;
	struct net_device *dev;
	struct hlist_head *head = dev_index_hash(net, ifindex);

	hlist_for_each_entry_rcu(dev, p, head, index_hlist)
		if (dev->ifindex == ifindex)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_get_by_index_rcu);


/**
 *	dev_get_by_index - find a device by its ifindex
 *	@net: the applicable net namespace
 *	@ifindex: index of device
 *
 *	Search for an interface by index. Returns NULL if the device
 *	is not found or a pointer to the device. The device returned has
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */

struct net_device *dev_get_by_index(struct net *net, int ifindex)
{
	struct net_device *dev;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifindex);
	if (dev)
		dev_hold(dev);
	rcu_read_unlock();
	return dev;
}
EXPORT_SYMBOL(dev_get_by_index);

/**
 *	dev_getbyhwaddr - find a device by its hardware address
 *	@net: the applicable net namespace
 *	@type: media type of device
 *	@ha: hardware address
 *
 *	Search for an interface by MAC address. Returns NULL if the device
 *	is not found or a pointer to the device. The caller must hold the
 *	rtnl semaphore. The returned device has not had its ref count increased
 *	and the caller must therefore be careful about locking
 *
 *	BUGS:
 *	If the API was consistent this would be __dev_get_by_hwaddr
 */

struct net_device *dev_getbyhwaddr(struct net *net, unsigned short type, char *ha)
{
	struct net_device *dev;

	ASSERT_RTNL();

	for_each_netdev(net, dev)
		if (dev->type == type &&
		    !memcmp(dev->dev_addr, ha, dev->addr_len))
			return dev;

	return NULL;
}
EXPORT_SYMBOL(dev_getbyhwaddr);
/*
  * »ñÈ¡ÍøÂçÉè±¸
  */
struct net_device *__dev_getfirstbyhwtype(struct net *net, unsigned short type)
{
	struct net_device *dev;

	ASSERT_RTNL();
	for_each_netdev(net, dev)
		if (dev->type == type)
			return dev;

	return NULL;
}
EXPORT_SYMBOL(__dev_getfirstbyhwtype);

struct net_device *dev_getfirstbyhwtype(struct net *net, unsigned short type)
{
	struct net_device *dev, *ret = NULL;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev)
		if (dev->type == type) {
			dev_hold(dev);
			ret = dev;
			break;
		}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(dev_getfirstbyhwtype);

/**
 *	dev_get_by_flags - find any device with given flags
 *	@net: the applicable net namespace
 *	@if_flags: IFF_* values
 *	@mask: bitmask of bits in if_flags to check
 *
 *	Search for any interface with the given flags. Returns NULL if a device
 *	is not found or a pointer to the device. The device returned has
 *	had a reference added and the pointer is safe until the user calls
 *	dev_put to indicate they have finished with it.
 */
    /*
      * ¸ù¾İ±êÖ¾»ñÈ¡ÍøÂçÉè±¸
      */

struct net_device *dev_get_by_flags(struct net *net, unsigned short if_flags,
				    unsigned short mask)
{
	struct net_device *dev, *ret;

	ret = NULL;
	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (((dev->flags ^ if_flags) & mask) == 0) {
			dev_hold(dev);
			ret = dev;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(dev_get_by_flags);

/**
 *	dev_valid_name - check if name is okay for network device
 *	@name: name string
 *
 *	Network device names need to be valid file names to
 *	to allow sysfs to work.  We also disallow any kind of
 *	whitespace.
 *///¼ì²éÍøÂçÉè±¸ÃûÊÇ·ñÓĞĞ§
int dev_valid_name(const char *name)
{
	if (*name == '\0')
		return 0;
	if (strlen(name) >= IFNAMSIZ)
		return 0;
	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return 0;

	while (*name) {
		if (*name == '/' || isspace(*name))
			return 0;
		name++;
	}
	return 1;
}
EXPORT_SYMBOL(dev_valid_name);

/**
 *	__dev_alloc_name - allocate a name for a device
 *	@net: network namespace to allocate the device name in
 *	@name: name format string
 *	@buf:  scratch buffer and result name string
 *
 *	Passed a format string - eg "lt%d" it will try and find a suitable
 *	id. It scans list of devices to build up a free map, then chooses
 *	the first empty slot. The caller must hold the dev_base or rtnl lock
 *	while allocating the name and adding the device in order to avoid
 *	duplicates.
 *	Limited to bits_per_byte * page size devices (ie 32K on most platforms).
 *	Returns the number of the unit assigned or a negative errno code.
 */

static int __dev_alloc_name(struct net *net, const char *name, char *buf)
{
	int i = 0;
	const char *p;
	const int max_netdevices = 8*PAGE_SIZE;
	unsigned long *inuse;
	struct net_device *d;

         /* 
        * ÔÚ×¢²áÍøÂçÉè±¸Ê±£¬Õâ¸öµØ·½µÄµ÷ÓÃÓĞĞ©ÖØ¸´¡£
        * register_netdevÖĞÒÑ¼ÆËã¹ıÒ»´Î '%'µÄÎ»ÖÃ¡£
        *
        */
	p = strnchr(name, IFNAMSIZ-1, '%');
	if (p) {
		/*
		 * Verify the string as this thing may have come from
		 * the user.  There must be either one "%d" and no other "%"
		 * characters.
		 */
		 /*
		 * ¸ñÊ½×Ö·û´®Ö»Ö§³Ö"name%d"µÄ¸ñÊ½£¬ËùÒÔ
		 * Èç¹ûÏÂ¸ö×Ö·û²»ÊÇ'd'»òÕß£¬ÔÚÖ®ºó»¹ÓĞ
		 * '%'¸ñÊ½´®£¬ÔòËµÃ÷name×Ö·û´®²»ºÏ·¨
		 *
		 */
		if (p[1] != 'd' || strchr(p + 2, '%'))
			return -EINVAL;

		/* Use one page as a bit array of possible slots */
		inuse = (unsigned long *) get_zeroed_page(GFP_ATOMIC);
		if (!inuse)
			return -ENOMEM;

		for_each_netdev(net, d) {
                     /* 
                      * Èç¹ûd->nameÖĞµÄ×Ö·û´®Ç°×º(²»°üÀ¨ºóÃæµÄÊı×Ö)
                      * ºÍnameÖĞµÄÇ°×º(²»°üÀ¨"%d")²»ÏàÍ¬£¬»òÕßd->nameÖĞ
                      * Ç°×ºÖ®ºóÃ»ÓĞÊı×Ö£¬Ôò·µ»ØÖµÎª0£¬·ñÔò·µ»ØµÄ
                      * ÊÇ¶Áµ½µÄÊı×ÖµÄ¸öÊı£¬ÕâÀïÓ¦¸ÃÊÇ1¡£Èç¹ûÇ°×º
                      * ²»Í¬»òÕßÃ»ÓĞÊı×Ö£¬ĞÂ×¢²áµÄÉè±¸¿Ï¶¨²»»áºÍd
                      * Ãû³Æ³åÍ»£¬Ò²¾Í²»ĞèÒª×öºóÃæµÄ½â¾ö³åÍ»µÄ²Ù×÷ÁË
                      */
			if (!sscanf(d->name, name, &i))
				continue;
                     /* ÕâÀïi´æ´¢ÊÇdµÄÉè±¸id */
			if (i < 0 || i >= max_netdevices)
				continue;

			/*  avoid cases where sscanf is not exact inverse of printf */
			snprintf(buf, IFNAMSIZ, name, i);
                    /* 
                     * Í¨¹ıÇ°ÃæµÄsscanfµ÷ÓÃÖªµÀ£¬d->nameºÍnameµÄÇ°×ºÏàÍ¬,
                     * ²¢ÇÒd->nameºóÃæÊÇÊı×Ö£¬µ«ÊÇÔÚd->nameÖĞµÄ×Ö·û´®ÓĞ
                     * ¿ÉÄÜÔÚÊı×ÖºóÃæ»¹ÓĞÓ¢ÎÄ×Ö·û£¬ÀıÈç"eth1n",ËùÒÔÕâÀï
                     * ÒªÔÙ½øĞĞÒ»´Î±È¶Ô£¬Ö»ÓĞÔÚd->nameµÄ×Ö·û´®ÊÇÒÔÊı×Ö½áÎ²
                     * Ê±²ÅĞèÒª¼ÌĞø½øĞĞ³åÍ»´¦Àí
                     */
			if (!strncmp(buf, d->name, IFNAMSIZ))
				set_bit(i, inuse);
		}

		i = find_first_zero_bit(inuse, max_netdevices);
		free_page((unsigned long) inuse);
	}

	/*
	  * ½«ÕÒµ½µÄ¿ÉÓÃÉè±¸IDºÍÃû³ÆÇ°×ºÊä³ö
	  * µ½bufÖĞ£¬Ò²¾ÍÊÇÉÏ²ã´«µİ¹ıÀ´µÄÓÃÀ´
	  * ´æ´¢Éè±¸Ãû³ÆµÄÄÚ´æ¡£
	  */
	snprintf(buf, IFNAMSIZ, name, i);
       /* 
        * Í¨¹ıÃû³Æ²éÕÒÊÇ·ñÒÑ´æÔÚÃû³ÆÏàÍ¬µÄÉè±¸£¬
        * Èç¹ûÃ»ÓĞÕÒµ½£¬ÔòËµÃ÷ÕÒµ½µÄÉè±¸idÊÇÎ¨Ò»µÄ
        */
	if (!__dev_get_by_name(net, buf))
		return i;

	/* It is possible to run out of possible slots
	 * when the name is long and there isn't enough space left
	 * for the digits, or if all bits are used.
	 */
	return -ENFILE;
}

/**
 *	dev_alloc_name - allocate a name for a device
 *	@dev: device
 *	@name: name format string
 *
 *	Passed a format string - eg "lt%d" it will try and find a suitable
 *	id. It scans list of devices to build up a free map, then chooses
 *	the first empty slot. The caller must hold the dev_base or rtnl lock
 *	while allocating the name and adding the device in order to avoid
 *	duplicates.
 *	Limited to bits_per_byte * page size devices (ie 32K on most platforms).
 *	Returns the number of the unit assigned or a negative errno code.
 */

int dev_alloc_name(struct net_device *dev, const char *name)
{
	char buf[IFNAMSIZ];
	struct net *net;
	int ret;

	BUG_ON(!dev_net(dev));
	net = dev_net(dev);
	ret = __dev_alloc_name(net, name, buf);
	if (ret >= 0)
		strlcpy(dev->name, buf, IFNAMSIZ);
	return ret;
}
EXPORT_SYMBOL(dev_alloc_name);

static int dev_get_valid_name(struct net_device *dev, const char *name, bool fmt)
{
	struct net *net;

	BUG_ON(!dev_net(dev));
	net = dev_net(dev);

	if (!dev_valid_name(name))
		return -EINVAL;

	if (fmt && strchr(name, '%'))
		return dev_alloc_name(dev, name);
	else if (__dev_get_by_name(net, name))
		return -EEXIST;
	else if (dev->name != name)
		strlcpy(dev->name, name, IFNAMSIZ);

	return 0;
}

/**
 *	dev_change_name - change name of a device
 *	@dev: device
 *	@newname: name (or format string) must be at least IFNAMSIZ
 *
 *	Change name of a device, can pass format strings "eth%d".
 *	for wildcarding.
 */
int dev_change_name(struct net_device *dev, const char *newname)
{
	char oldname[IFNAMSIZ];
	int err = 0;
	int ret;
	struct net *net;

	ASSERT_RTNL();
	BUG_ON(!dev_net(dev));

	net = dev_net(dev);
	if (dev->flags & IFF_UP)
		return -EBUSY;

	if (strncmp(newname, dev->name, IFNAMSIZ) == 0)
		return 0;

	memcpy(oldname, dev->name, IFNAMSIZ);

	err = dev_get_valid_name(dev, newname, 1);
	if (err < 0)
		return err;

rollback:
	ret = device_rename(&dev->dev, dev->name);
	if (ret) {
		memcpy(dev->name, oldname, IFNAMSIZ);
		return ret;
	}

	write_lock_bh(&dev_base_lock);
	hlist_del(&dev->name_hlist);
	write_unlock_bh(&dev_base_lock);

	synchronize_rcu();

	write_lock_bh(&dev_base_lock);
	hlist_add_head_rcu(&dev->name_hlist, dev_name_hash(net, dev->name));
	write_unlock_bh(&dev_base_lock);

	ret = call_netdevice_notifiers(NETDEV_CHANGENAME, dev);
	ret = notifier_to_errno(ret);

	if (ret) {
		/* err >= 0 after dev_alloc_name() or stores the first errno */
		if (err >= 0) {
			err = ret;
			memcpy(dev->name, oldname, IFNAMSIZ);
			goto rollback;
		} else {
			printk(KERN_ERR
			       "%s: name change rollback failed: %d.\n",
			       dev->name, ret);
		}
	}

	return err;
}

/**
 *	dev_set_alias - change ifalias of a device
 *	@dev: device
 *	@alias: name up to IFALIASZ
 *	@len: limit of bytes to copy from info
 *
 *	Set ifalias for a device,
 */
int dev_set_alias(struct net_device *dev, const char *alias, size_t len)
{
	ASSERT_RTNL();

	if (len >= IFALIASZ)
		return -EINVAL;

	if (!len) {
		if (dev->ifalias) {
			kfree(dev->ifalias);
			dev->ifalias = NULL;
		}
		return 0;
	}

	dev->ifalias = krealloc(dev->ifalias, len + 1, GFP_KERNEL);
	if (!dev->ifalias)
		return -ENOMEM;

	strlcpy(dev->ifalias, alias, len+1);
	return len;
}


/**
 *	netdev_features_change - device changes features
 *	@dev: device to cause notification
 *
 *	Called to indicate a device has changed features.
 */
void netdev_features_change(struct net_device *dev)
{
	call_netdevice_notifiers(NETDEV_FEAT_CHANGE, dev);
}
EXPORT_SYMBOL(netdev_features_change);

/**
 *	netdev_state_change - device changes state
 *	@dev: device to cause notification
 *
 *	Called to indicate a device has changed state. This function calls
 *	the notifier chains for netdev_chain and sends a NEWLINK message
 *	to the routing socket.
 */
void netdev_state_change(struct net_device *dev)
{
	if (dev->flags & IFF_UP) {
		call_netdevice_notifiers(NETDEV_CHANGE, dev);
		rtmsg_ifinfo(RTM_NEWLINK, dev, 0);
	}
}
EXPORT_SYMBOL(netdev_state_change);

int netdev_bonding_change(struct net_device *dev, unsigned long event)
{
	return call_netdevice_notifiers(event, dev);
}
EXPORT_SYMBOL(netdev_bonding_change);

/**
 *	dev_load 	- load a network module
 *	@net: the applicable net namespace
 *	@name: name of interface
 *
 *	If a network interface is not present and the process has suitable
 *	privileges this function loads the module. If module loading is not
 *	available in this kernel then it becomes a nop.
 */

void dev_load(struct net *net, const char *name)
{
	struct net_device *dev;
	int no_module;

	rcu_read_lock();
	dev = dev_get_by_name_rcu(net, name);
	rcu_read_unlock();
	no_module = !dev;
	if (no_module && capable(CAP_NET_ADMIN))
		no_module = request_module("netdev-%s", name);
	if (no_module && capable(CAP_SYS_MODULE)) {
		if (!request_module("%s", name))
			pr_err("Loading kernel module for a network device "
"with CAP_SYS_MODULE (deprecated).  Use CAP_NET_ADMIN and alias netdev-%s "
"instead\n", name);
	}
}
EXPORT_SYMBOL(dev_load);

/**
 *	dev_open	- prepare an interface for use.
 *	@dev:	device to open
 *
 *	Takes a device from down to up state. The device's private open
 *	function is invoked and then the multicast lists are loaded. Finally
 *	the device is moved into the up state and a %NETDEV_UP message is
 *	sent to the netdev notifier chain.
 *
 *	Calling this function on an active interface is a nop. On a failure
 *	a negative errno code is returned.
 */
/*
  * Éè±¸Ò»µ©×¢²áºó¼´¿ÉÊ¹ÓÃ£¬µ«±ØĞëÔÚÓÃ»§
  * »òÓÃ»§¿Õ¼äÓ¦ÓÃ³ÌĞòÊ¹ÄÜºó²Å¿ÉÒÔÊÕ·¢Êı¾İ
  * ÒòÎª×¢²áµ½ÏµÍ³ÖĞµÄÍøÂçÉè±¸£¬Æä³õÊ¼
  * ×´Ì¬ÊÇ¹Ø±ÕµÄ£¬´ËÊ±ÊÇ²»ÄÜ´«ÊäÊı¾İµÄ£¬±ØĞë
  * ¼¤»îºó£¬ÍøÂçÉè±¸²ÅÄÜ½øĞĞÊı¾İµÄ´«Êä¡£ÔÚ
  * Ó¦ÓÃ²ã£¬¿ÉÒÔÍ¨¹ıifconfig upÃüÁî(×îÖÕÊÇÍ¨¹ıioctl
  * µÄSIOCSIFFLAGS)À´¼¤»îÍøÂçÉè±¸¡£¶øSIOCIFFLAGSÃüÁî
  * ÊÇÍ¨¹ıdev_change_flags()µ÷ÓÃdev_open()À´¼¤»îÍøÂçÉè±¸¡£
  * dev_open()½«ÍøÂçÉè±¸´Ó¹Ø±Õ×´Ì¬×ªµ½¼¤»î×´Ì¬£¬
  * ²¢·¢ËÍÒ»¸öNETDEV_UPÏûÏ¢µ½ÍøÂçÉè±¸×´Ì¬¸Ä±ä
  * Í¨ÖªÁ´ÉÏ¡£
  *////ic_dev_ioctl->dev_ioctl->dev_ifsioc->dev_change_flags
int __dev_open(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int ret;

	ASSERT_RTNL();

	/*
	 *	Is it already up?
	 */
	/*
	  * Èç¹ûÍøÂçÉè±¸ÒÑ¾­ÆôÓÃ£¬ÔòÎŞĞèÔÙ¼ÇĞÔ²Ù×÷¡£
	  */
	if (dev->flags & IFF_UP)
		return 0;

	/*
	 *	Is it even present?
	 */
	/*
	  * Èç¹ûÍøÂçÉè±¸ÒÑ¾­¹ÒÆğ£¬Ôò²»ÄÜ±»¼¤»î¡£
	  */
	if (!netif_device_present(dev))
		return -ENODEV;

	/*
	  * ·¢ËÍNETDEV_PRE_UPÊÂ¼şÍ¨Öª
	  */
	ret = call_netdevice_notifiers(NETDEV_PRE_UP, dev);
	ret = notifier_to_errno(ret);
	if (ret)
		return ret;

	/*
	 *	Call device private open method
	 */
	/*
	  * Éè±¸ÍøÂçÉè±¸µÄÆôÓÃ×´Ì¬±êÖ¾¡£Èç¹û
	  * ÊµÏÖopenº¯Êı£¬Ôò¸ù¾İ¾ßÌåÓ²¼ş×¢²á
	  * ÏµÍ³×ÊÔ´£¬Ê¹ÄÜÓ²¼ş£¬²¢¶ÔÉè±¸×÷
	  * ÆäËûµÄÒ»Ğ©ÉèÖÃ¡£
	  */
	set_bit(__LINK_STATE_START, &dev->state);

	if (ops->ndo_validate_addr)
		ret = ops->ndo_validate_addr(dev);

	if (!ret && ops->ndo_open)
		ret = ops->ndo_open(dev);

	/*
	 *	If it went open OK then:
	 */

	/*
	  * Èç¹ûÆôÓÃÍøÂçÉè±¸³É¹¦£¬ÔòÉèÖÃÍøÂç
	  * Éè±¸µÄÒÑÆôÓÃ±êÖ¾£¬²¢¸üĞÂ×é²¥µØÖ·ÁĞ±í
	  * µ½ÍøÂçÉè±¸ÖĞ£¬ÍøÂçÉè±¸ÉèÖÃÎª´«µİ×´Ì¬¡£
	  * µ÷ÓÃdev_activate()³õÊ¼»¯ÓÃÓÚÁ÷Á¿¿ØÖÆµÄÅÅ¶Ó
	  * ¹æÔò£¬²¢Æô¶¯¶¨Ê±Æ÷¡£Èç¹ûÓÃ»§Ã»ÓĞ
	  * ÅäÖÃÁ÷Á¿¿ÉÄÜ¸ùÖÎ£¬ÔòÖ¸¶¨ÎªÄ¬ÈÏµÄ
	  * ÏÈ½øÏÈ³ö(FIFO)¶ÓÁĞ¡£×îºó£¬·¢ËÍNETDEV_UP
	  * ÏûÏ¢µ½ÍøÂçÉè±¸×´Ì¬¸Ä±äÍ¨ÖªÁ´ÉÏ£¬ÒÔ
	  * Í¨Öª¶ÔÍøÂçÉè±¸¸ĞĞËÈ¤µÄÆäËûÄÚºË×é¼ş¡£
	  */
	if (ret)
		clear_bit(__LINK_STATE_START, &dev->state);
	else {
		/*
		 *	Set the flags.
		 */
		dev->flags |= IFF_UP;

		/*
		 *	Enable NET_DMA
		 */
		net_dmaengine_get();

		/*
		 *	Initialize multicasting status
		 */
		dev_set_rx_mode(dev);

		/*
		 *	Wakeup transmit queue engine
		 */
		dev_activate(dev);

		/*
		 *	... and announce new interface.
		 */
		call_netdevice_notifiers(NETDEV_UP, dev);
	}

	return ret;
}

/**
 *	dev_open	- prepare an interface for use.
 *	@dev:	device to open
 *
 *	Takes a device from down to up state. The device's private open
 *	function is invoked and then the multicast lists are loaded. Finally
 *	the device is moved into the up state and a %NETDEV_UP message is
 *	sent to the netdev notifier chain.
 *
 *	Calling this function on an active interface is a nop. On a failure
 *	a negative errno code is returned.
 *////ic_dev_ioctl->dev_ioctl->dev_ifsioc->dev_change_flags
int dev_open(struct net_device *dev)
{
	int ret;

	/*
	 *	Is it already up?
	 */
	if (dev->flags & IFF_UP)
		return 0;

	/*
	 *	Open device
	 */
	ret = __dev_open(dev);
	if (ret < 0)
		return ret;

	/*
	 *	... and announce new interface.
	 */
	rtmsg_ifinfo(RTM_NEWLINK, dev, IFF_UP|IFF_RUNNING);
	call_netdevice_notifiers(NETDEV_UP, dev);

	return ret;
}
EXPORT_SYMBOL(dev_open);

static int __dev_c333lose(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	ASSERT_RTNL();
	might_sleep();

	/*
	 *	Tell people we are going down, so that they can
	 *	prepare to death, when device is still operating.
	 */
	call_netdevice_notifiers(NETDEV_GOING_DOWN, dev);

	clear_bit(__LINK_STATE_START, &dev->state);

	/* Synchronize to scheduled poll. We cannot touch poll list,
	 * it can be even on different cpu. So just clear netif_running().
	 *
	 * dev->stop() will invoke napi_disable() on all of it's
	 * napi_struct instances on this device.
	 */
	smp_mb__after_clear_bit(); /* Commit netif_running(). */

	dev_deactivate(dev);

	/*
	 *	Call the device specific close. This cannot fail.
	 *	Only if device is UP
	 *
	 *	We allow it to be called even after a DETACH hot-plug
	 *	event.
	 */
	if (ops->ndo_stop)
		ops->ndo_stop(dev);

	/*
	 *	Device is now down.
	 */

	dev->flags &= ~IFF_UP;

	/*
	 *	Shutdown NET_DMA
	 */
	net_dmaengine_put();

	return 0;
}

/**
 *	dev_close - shutdown an interface.
 *	@dev: device to shutdown
 *
 *	This function moves an active device into down state. A
 *	%NETDEV_GOING_DOWN is sent to the netdev notifier chain. The device
 *	is then deactivated and finally a %NETDEV_DOWN is sent to the notifier
 *	chain.
 */
/*
  * ÍøÂçÉè±¸Ò»µ©¹Ø±Õºó¾Í²»ÄÜ´«ÊäÊı¾İÁË¡£ÍøÂç
  * Éè±¸ÄÜ±»ÓÃ»§ÃüÁîÃ÷È·µØ»î±»ÆäËûÊÂ¼şÒşº¬µØ
  * ½ûÖ¹¡£ÔÚÓ¦ÓÃ²ã£¬¿ÉÒÔÍ¨¹ıifconfig downÃüÁî(×îÖÕ
  * ÊÇÍ¨¹ıioctl()µÄSIOCSIFFLAGS)À´¹Ø±ÕÍøÂçÉè±¸£¬»òÕß
  * ÔÚÍøÂçÉè±¸×¢ÏúÊ±±»½ûÖ¹¡£
  * SIOCSIFFLAGSÃüÁîÍ¨¹ıdev_change_flags()£¬¸ù¾İÍøÂçÉè±¸
  * µ±Ç°µÄ×´Ì¬À´È·¶¨µ÷ÓÃdev_close()¹Ø±ÕÍøÂçÉè±¸¡£
  * dev_close()½«ÍøÂçÉè±¸´Ó¼¤»î×´Ì¬×ª»»µ½¹Ø±Õ×´Ì¬£¬
  * ²¢·¢ËÍNETDEV_GOING_DOWNºÍNETDEV_DOWNÏûÏ¢µ½ÍøÂç
  * Éè±¸×´Ì¬¸Ä±äÍ¨ÖªÁ´ÉÏ¡£
  *///Ğ¶ÔØÄ£¿éµÄÊ±ºòÒ²»áµ÷ÓÃ¸Ãº¯Êı
int __dev_close(struct net_device *dev)///ic_dev_ioctl->dev_ioctl->dev_ifsioc->dev_change_flags
{
	const struct net_device_ops *ops = dev->netdev_ops;
	ASSERT_RTNL();

	might_sleep();

	/*
	  * ÈôÍøÂçÉè±¸Î´ÆôÓÃ£¬ÔòÎŞĞèÔÙ½øĞĞ²Ù×÷¡£
	  */
	if (!(dev->flags & IFF_UP))
		return 0;

	/*
	 *	Tell people we are going down, so that they can
	 *	prepare to death, when device is still operating.
	 */
	/*
	  * ÔÚ¹Ø±ÕÍøÂçÉè±¸Ö®Ç°£¬·¢ËÍNETDEV_GOING_DOWNÏûÏ¢
	  * µ½ÍøÂçÉè±¸×´Ì¬¸Ä±äÍ¨ÖªÁ´ÉÏ£¬ÒÔ±ãÍ¨Öª
	  * ¶ÔÉè±¸½ûÖ¹¸ĞĞËÈ¤µÄÄÚºË×é¼ş
	  */
	call_netdevice_notifiers(NETDEV_GOING_DOWN, dev);

	/*
	  * ½«ÍøÂçÉè±¸ÉèÖÃÎª½ûÖ¹´«µİÊı¾İ°ü
	  * ×´Ì¬£¬ÉèÖÃ¶ÔÓ¦±êÖ¾¡£
	  */
	clear_bit(__LINK_STATE_START, &dev->state);

	/* Synchronize to scheduled poll. We cannot touch poll list,
	 * it can be even on different cpu. So just clear netif_running().
	 *
	 * dev->stop() will invoke napi_disable() on all of it's
	 * napi_struct instances on this device.
	 */
	smp_mb__after_clear_bit(); /* Commit netif_running(). */

	/*
	  * µ÷ÓÃdev_deactivate()½ûÖ¹³ö¿Ú¶ÓÁĞ¹æÔò£¬È·±£
	  * ¸ÃÉè±¸²»ÔÙÓÃÓÚ´«Êä£¬²¢Í£Ö¹²»ÔÙĞèÒª
	  * µÄ¼à¿Ø¶¨Ê±Æ÷¡£
	  */
	dev_deactivate(dev);

	/*
	 *	Call the device specific close. This cannot fail.
	 *	Only if device is UP
	 *
	 *	We allow it to be called even after a DETACH hot-plug
	 *	event.
	 */
	if (ops->ndo_stop)
		ops->ndo_stop(dev);

	/*
	 *	Device is now down.
	 */
	/*
	  * ³É¹¦¹Ø±ÕÍøÂçÉè±¸ºóÈ¥µôÒÑÆôÓÃ±êÖ¾
	  */
	dev->flags &= ~IFF_UP;

	/*
	 * Tell people we are down
	 */
	/*
	  * Íê³É¹Ø±ÕÉè±¸ºó£¬·¢ËÍNETDEV_DOWNÏûÏ¢µ½
	  * ÍøÂçÉè±¸×´Ì¬¸Ä±äÍ¨ÖªÁ´ÉÏ£¬Í¨Öª
	  * ¶ÔÉè±¸½ûÖ¹¸ĞĞËÈ¤µÄÄÚºË×é¼ş¡£
	  */
	call_netdevice_notifiers(NETDEV_DOWN, dev);

	/*
	 *	Shutdown NET_DMA
	 */
	net_dmaengine_put();

	return 0;
}

/**
 *	dev_close - shutdown an interface.
 *	@dev: device to shutdown
 *
 *	This function moves an active device into down state. A
 *	%NETDEV_GOING_DOWN is sent to the netdev notifier chain. The device
 *	is then deactivated and finally a %NETDEV_DOWN is sent to the notifier
 *	chain.
 */
int dev_c22lose(struct net_device *dev)
{
	if (!(dev->flags & IFF_UP))
		return 0;

	__dev_close(dev);

	/*
	 * Tell people we are down
	 */
	rtmsg_ifinfo(RTM_NEWLINK, dev, IFF_UP|IFF_RUNNING); //Í¨¹ıdevÊÂ¼şÍ¨ÖªÁ´RTM_NEWLINKÍ¨Öª¸øÓ¦ÓÃ³ÌĞò£¬¸Ãdev×¢ÏúÁË
	call_netdevice_notifiers(NETDEV_DOWN, dev);

	return 0;
}
EXPORT_SYMBOL(dev_close);


/**
 *	dev_disable_lro - disable Large Receive Offload on a device
 *	@dev: device
 *
 *	Disable Large Receive Offload (LRO) on a net device.  Must be
 *	called under RTNL.  This is needed if received packets may be
 *	forwarded to another interface.
 */
void dev_disable_lro(struct net_device *dev)
{
	if (dev->ethtool_ops && dev->ethtool_ops->get_flags &&
	    dev->ethtool_ops->set_flags) {
		u32 flags = dev->ethtool_ops->get_flags(dev);
		if (flags & ETH_FLAG_LRO) {
			flags &= ~ETH_FLAG_LRO;
			dev->ethtool_ops->set_flags(dev, flags);
		}
	}
	WARN_ON(dev->features & NETIF_F_LRO);
}
EXPORT_SYMBOL(dev_disable_lro);


static int dev_boot_phase = 1;//0±êÊ¶ÍøÂçÉè±¸³õÊ¼»¯ÒÑÍê³É

/*
 *	Device change register/unregister. These are not inline or static
 *	as we export them to the world.
 */

/**
 *	register_netdevice_notifier - register a network notifier block
 *	@nb: notifier
 *
 *	Register a notifier to be called when network device events occur.
 *	The notifier passed is linked into the kernel structures and must
 *	not be reused until it has been unregistered. A negative errno code
 *	is returned on a failure.
 *
 * 	When registered all registration and up events are replayed
 *	to the new notifier to allow device to have a race free
 *	view of the network device list.
 */ //ÄÚºË×é¼ş¶ÔÓÉregister_netdevice_notifier ºÍ unregister_netdevice_notifier·Ö±ğ×¢²á¡¢×¢ÏúµÄÍ¨ÖªÁ´ÖĞµÄÊÂ¼ş¸ĞĞËÈ¤¡£
//yang ½«´¦ÀíÍøÂçÉè±¸ÊÂ¼şµÄº¯Êı×¢²áµ½netdev_chainÍ¨ÖªÁ´ÖĞ  ÊÂ¼şÍ¨ÖªÁ´(notifier chain)
¡//×¢²áÊ±¼äÍ¨ÖªÁ¬Êµ¼ÊÉÏ¾ÍÊÇ°ÑnbÌí¼Óµ½netdev_chainÁ´±íÖĞ£¬È»ºóÈÃËùÓĞµÄdevÉè±¸Ö´ĞĞnb->notifier_call()ÖĞµÄÊÂ¼şº¯Êı¡£¿ÉÒÔ²Î¿¼pppoe_init

/*
LinuxÄÚºËÖĞ¸÷¸ö×ÓÏµÍ³Ïà»¥ÒÀÀµ£¬µ±ÆäÖĞÄ³¸ö×ÓÏµÍ³×´Ì¬·¢Éú¸Ä±äÊ±£¬¾Í±ØĞëÊ¹ÓÃÒ»¶¨µÄ»úÖÆ¸æÖªÊ¹ÓÃÆä·şÎñµÄÆäËû×ÓÏµÍ³£¬ÒÔ±ãÆäËû×ÓÏµÍ³²ÉÈ¡ÏàÓ¦µÄ´ëÊ©¡£
ÎªÂú×ãÕâÑùµÄĞèÇó£¬ÄÚºËÊµÏÖÁËÊÂ¼şÍ¨ÖªÁ´»úÖÆ£¨notificationchain£©¡£
*/
/*
LinuxµÄÍøÂç×ÓÏµÍ³Ò»¹²ÓĞ3¸öÍ¨ÖªÁ´£º±íÊ¾ipv4µØÖ··¢Éú±ä»¯Ê±µÄinetaddr_chain£»±íÊ¾ipv6µØÖ··¢Éú±ä»¯µÄinet6addr_chain£»»¹ÓĞ±íÊ¾Éè±¸×¢²á¡¢
×´Ì¬±ä»¯µÄnetdev_chain¡£

Í¨ÖªÁ´¼¼Êõ¿ÉÒÔ¸ÅÀ¨Îª£ºÊÂ¼şµÄ±»Í¨ÖªÕß½«ÊÂ¼ş·¢ÉúÊ±Ó¦¸ÃÖ´ĞĞµÄ²Ù×÷Í¨¹ıº¯ÊıÖ¸Õë·½Ê½±£´æÔÚÁ´±í£¨Í¨ÖªÁ´£©ÖĞ£¬
È»ºóµ±ÊÂ¼ş·¢ÉúÊ±Í¨ÖªÕßÒÀ´ÎÖ´ĞĞÁ´±íÖĞÃ¿Ò»¸öÔªËØµÄ»Øµ÷º¯ÊıÍê³ÉÍ¨Öª
*/
int register_netdevice_notifier(struct notifier_block *nb)//ºÍcall_netdevice_notifiersÅäºÏÊ¹ÓÃ
{
	struct net_device *dev;
	struct net_device *last;
	struct net *net;
	int err;

	rtnl_lock();
	err = raw_notifier_chain_register(&netdev_chain, nb);//°´ÕÕnb->priorityÓÅÏÈ¼¶°Ñnb¼ÓÈëµ½netdev_chainÁ´±íÖĞ
	if (err)
		goto unlock;
	if (dev_boot_phase)
		goto unlock;
	for_each_net(net) { /* ×¢ÒâÕâÀïÈÃËùÓĞµÄdevÉè±¸¶¼Ö´ĞĞÁËÒ»±énb->notifier_call£¬ ¶øcall_netdevice_notifiersÊÇÈÃnetdev_chainÖĞµÄËùÓĞ½Úµãnotifer_callÖ´ĞĞÒ»±é*/
		for_each_netdev(net, dev) {
			err = nb->notifier_call(nb, NETDEV_REGISTER, dev);
			err = notifier_to_errno(err);
			if (err)
				goto rollback;

			if (!(dev->flags & IFF_UP))
				continue;

			nb->notifier_call(nb, NETDEV_UP, dev);
		}
	}

unlock:
	rtnl_unlock();
	return err;

rollback:
	last = dev;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev == last)
				break;

			if (dev->flags & IFF_UP) {
				nb->notifier_call(nb, NETDEV_GOING_DOWN, dev);
				nb->notifier_call(nb, NETDEV_DOWN, dev);
			}
			nb->notifier_call(nb, NETDEV_UNREGISTER, dev);
			nb->notifier_call(nb, NETDEV_UNREGISTER_BATCH, dev);
		}
	}

	raw_notifier_chain_unregister(&netdev_chain, nb);
	goto unlock;
}
EXPORT_SYMBOL(register_netdevice_notifier);

/**
 *	unregister_netdevice_notifier - unregister a network notifier block
 *	@nb: notifier
 *
 *	Unregister a notifier previously registered by
 *	register_netdevice_notifier(). The notifier is unlinked into the
 *	kernel structures and may then be reused. A negative errno code
 *	is returned on a failure.
 */

int unregister_netdevice_notifier(struct notifier_block *nb)
{
	int err;

	rtnl_lock();
	err = raw_notifier_chain_unregister(&netdev_chain, nb);
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(unregister_netdevice_notifier);

/**
 *	call_netdevice_notifiers - call all network notifier blocks
 *      @val: value passed unmodified to notifier function
 *      @dev: net_device pointer passed unmodified to notifier function
 *
 *	Call all network notifier blocks.  Parameters and return value
 *	are as for raw_notifier_call_chain().
 Í¨ÖªÁ´¼¼Êõ¿ÉÒÔ¸ÅÀ¨Îª£ºÊÂ¼şµÄ±»Í¨ÖªÕß½«ÊÂ¼ş·¢ÉúÊ±Ó¦¸ÃÖ´ĞĞµÄ²Ù×÷Í¨¹ıº¯ÊıÖ¸Õë·½Ê½±£´æÔÚÁ´±í£¨Í¨ÖªÁ´£©ÖĞ£¬
 È»ºóµ±ÊÂ¼ş·¢ÉúÊ±Í¨ÖªÕßÒÀ´ÎÖ´ĞĞÁ´±íÖĞÃ¿Ò»¸öÔªËØµÄ»Øµ÷º¯ÊıÍê³ÉÍ¨Öª
 */
int call_netdevice_notifiers(unsigned long val, struct net_device *dev)//ºÍregister_netdevice_notifierÅäºÏÊ¹ÓÃ
{
	ASSERT_RTNL();
	return raw_notifier_call_chain(&netdev_chain, val, dev);
}

/* When > 0 there are consumers of rx skb time stamps */
static atomic_t netstamp_needed = ATOMIC_INIT(0);

void net_enable_timestamp(void)
{
	atomic_inc(&netstamp_needed);
}
EXPORT_SYMBOL(net_enable_timestamp);

void net_disable_timestamp(void)
{
	atomic_dec(&netstamp_needed);
}
EXPORT_SYMBOL(net_disable_timestamp);

static inline void net_timestamp_set(struct sk_buff *skb)
{
	if (atomic_read(&netstamp_needed))
		__net_timestamp(skb);
	else
		skb->tstamp.tv64 = 0;
}

static inline void net_timestamp_check(struct sk_buff *skb)
{
	if (!skb->tstamp.tv64 && atomic_read(&netstamp_needed))
		__net_timestamp(skb);
}

/**
 * dev_forward_skb - loopback an skb to another netif
 *
 * @dev: destination network device
 * @skb: buffer to forward
 *
 * return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_DROP     (packet was dropped, but freed)
 *
 * dev_forward_skb can be used for injecting an skb from the
 * start_xmit function of one device into the receive queue
 * of another device.
 *
 * The receiving device may be in another namespace, so
 * we have to clear all information in the skb that could
 * impact namespace isolation.
 */
int dev_forward_skb(struct net_device *dev, struct sk_buff *skb)
{
	skb_orphan(skb);
	nf_reset(skb);

	if (!(dev->flags & IFF_UP) ||
	    (skb->len > (dev->mtu + dev->hard_header_len + VLAN_HLEN))) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}
	skb_set_dev(skb, dev);
	skb->tstamp.tv64 = 0;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, dev);
	return netif_rx(skb);
}
EXPORT_SYMBOL_GPL(dev_forward_skb);

/*
 *	Support routine. Sends outgoing frames to any network
 *	taps currently in use.
 */
/*
  * ¶ÔÓÚÍ¨¹ısocket(AF_PACKET£¬ SOCK_RAW£¬htons(ETH_P_ALL))´´½¨
  * µÄÔ­Ê¼Ì×½Ó×Ö£¬²»µ«¿ÉÒÔ½ÓÊÕ´ÓÍâ²¿ÊäÈëµÄÊı¾İ°ü£¬
  * ¶øÇÒ¶ÔÓÚÓÉ±¾µØÊä³öµÄÊı¾İ°ü£¬Èç¹ûÂú×ãÌõ¼ş£¬Ò²Í¬Ñù
  * ¿ÉÒÔ½ÓÊÕ¡£
  * dev_queue_xmit_nit()¾ÍÊÇÓÃÀ´½ÓÊÕÓÉ±¾µØÊä³öµÄÊı¾İ°ü£¬ÔÚÁ´Â·²ã
  * µÄÊä³ö¹ı³ÌÖĞ£¬»áµ÷ÓÃ´Ëº¯Êı£¬½«Âú×ãÌõ¼şµÄÊı¾İ°üÊäÈë
  * µ½RAWÌ×½Ó×Ö¡£
  * @skb:´ıÊä³öµÄÊı¾İ°ü£¬Èç¹ûÂú×ãÌõ¼ş£¬ÔòÊäÈëµ½Ô­Ê¼Ì×½Ó×Ö
  * @dev:Êä³öÊı¾İ°üµÄÍøÂçÉè±¸£¬Èç¹ûÂú×ãÌõ¼ş£¬Ôò´Ó¸ÃÍøÂç
  *          Éè±¸ÊäÈëµ½Ô­Ê¼Ì×½Ó×Ö
  */
static void dev_queue_xmit_nit(struct sk_buff *skb, struct net_device *dev)
{
	struct packet_type *ptype;

#ifdef CONFIG_NET_CLS_ACT
	/*
	  * ¼ÇÂ¼Êı¾İ°üÊäÈëµÄÊ±¼ä´Á
	  */
	if (!(skb->tstamp.tv64 && (G_TC_FROM(skb->tc_verd) & AT_INGRESS)))
		net_timestamp(skb);
#else
	net_timestamp(skb);
#endif

	rcu_read_lock();
	/*
	  * ±éÀúptype_allÁ´±í£¬²éÕÒËùÓĞ·ûºÏÊäÈëÌõ¼şµÄ
	  * Ô­Ê¼Ì×½Ó×Ö£¬²¢Ñ­»·½«Êı¾İ°üÊäÈëµ½Âú×ãÌõ¼ş
	  * µÄÌ×½Ó×Ö
	  */
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		/* Never send packets back to the socket
		 * they originated from - MvS (miquels@drinkel.ow.org)
		 */
		/*
		  * Êı¾İ°üµÄÊä³öÉè±¸ÓëÌ×½Ó×ÖµÄÊäÈëÉè±¸Ïà·û
		  * »òÕßÌ×½Ó×Ö²»Ö¸¶¨ÊäÈëÉè±¸£¬²¢ÇÒ¸ÃÊı¾İ°ü
		  * ²»ÊÇÓÉµ±Ç°ÓÃÓÚ±È½ÏµÄÌ×½Ó×ÖÊä³öµÄ(ÓÉ
		  * Ô­Ê¼Ì×½Ó×ÖÊä³öµÄÊı¾İ°ü²»»áÔÙ´ÎÊäÈë¸ø×Ô¼º)£¬
		  * ´ËÊ±¸ÃÔ­Ê¼Ì×½Ó×ÖÂú×ãÌõ¼ş£¬Êı¾İ°ü¿ÉÒÔÊäÈë
		  */ /*×¢ÒâÕâÀï²¢Ã»ÓĞÒªÇóptype->type == type£¬ËùÒÔ½ÓÊÕµ½µÄ°üÖ»ÒªÓĞ×¢²áETH_P_ALLĞ­Òé£¬ËùÓĞµÄ°ü¶¼»á×ßµ½deliver_skb*/
		if ((ptype->dev == dev || !ptype->dev) &&
		    (ptype->af_packet_priv == NULL ||
		     (struct sock *)ptype->af_packet_priv != skb->sk)) {
			/*
			  * ÓÉÓÚ¸ÃÊı¾İ°üÊ±¶îÍâÊäÈëµ½Õâ¸öÔ­Ê¼Ì×½Ó×ÖµÄ£¬
			  * Òò´ËĞèÒª¿ËÂ¡Ò»¸öÊı¾İ°ü¡£
			  */
			struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
			if (!skb2)
				break;

			/* skb->nh should be correctly
			   set by sender, so that the second statement is
			   just protection against buggy protocols.
			 */
			/*
			  * Ğ£ÑéÊı¾İ°üÊÇ·ñÓĞĞ§
			  */
			skb_reset_mac_header(skb2);

			if (skb_network_header(skb2) < skb2->data ||
			    skb2->network_header > skb2->tail) {
				if (net_ratelimit())
					printk(KERN_CRIT "protocol %04x is "
					       "buggy, dev %s\n",
					       skb2->protocol, dev->name);
				skb_reset_network_header(skb2);
			}

			/*
			  * ½«Êı¾İ°üÊäÈëµ½Ô­Ê¼Ì×½Ó×Ö
			  */
			skb2->transport_header = skb2->network_header;
			skb2->pkt_type = PACKET_OUTGOING;
			ptype->func(skb2, skb->dev, ptype, skb->dev);
		}
	}
	rcu_read_unlock();
}

/*
 * Routine to help set real_num_tx_queues. To avoid skbs mapped to queues
 * greater then real_num_tx_queues stale skbs on the qdisc must be flushed.
 */
void netif_set_real_num_tx_queues(struct net_device *dev, unsigned int txq)
{
	unsigned int real_num = dev->real_num_tx_queues;

	if (unlikely(txq > dev->num_tx_queues))
		;
	else if (txq > real_num)
		dev->real_num_tx_queues = txq;
	else if (txq < real_num) {
		dev->real_num_tx_queues = txq;
		qdisc_reset_all_tx_gt(dev, txq);
	}
}
EXPORT_SYMBOL(netif_set_real_num_tx_queues);

//°ÑQdiscÖĞµÄÊı¾İ·ÅÈëcpu sdµÄoutput_queue_tailpÊä³ö¶ÓÁĞ£¬½«¶ÓÁĞ¼ÓÈë·¢ËÍÈíÖĞ¶ÏNET_TX_SOFTIRQµÄ´¦Àí¶ÓÁĞ£¬µ±ÈíÖĞ¶Ï±»Ö´ĞĞÊ±£¬¶ÓÁĞÓÖ»á¼ÌĞø·¢ËÍÊı¾İ°ü¡£__netif_reschedule
/*
ÓÉÓÚÈíÖĞ¶Ï±»¼¤»î£¬ÈíÖĞ¶ÏµÄÓÅÏÈ¼¶½ö´ÎÓÚÓ²ÖĞ¶Ï£¬ÕâÑù¾Í±£Ö¤ÁË¶ÓÁĞ»á±»¼°Ê±µÄÔËĞĞ£¬¼´±£Ö¤ÁËÊı¾İ°ü»á±»¼°Ê±µÄ·¢ËÍ¡£
*///¼¤»î·¢ËÍÈí¼şÖĞµÄ£¬×îÖÕµ÷ÓÃnet_tx_action
//dev_queue_xmit -> __dev_xmit_skb -> __qdisc_run×îÖÕµ÷ÓÃµ½¸Ãº¯Êı£¬°ÑÁ÷¿Ø¶ÔÏóQdiscÌí¼Óµ½CPUÈíÖĞ¶ÏµÄoutput_queue
static inline void __netif_reschedule(struct Qdisc *q)
{
	struct softnet_data *sd;
	unsigned long flags;

    /*
      * ½«ÍøÂçÉè±¸Á´½Óµ½softnet_dataÖĞµÄoutput_queu
      * ¶ÓÁĞÉÏ£¬È»ºó¼¤»îÍøÂçÊä³öÈíÖĞ¶Ï¶Ô¸Ã
      * ¶ÓÁĞ½øĞĞ´¦Àí¡£
      */
	local_irq_save(flags);
	sd = &__get_cpu_var(softnet_data);
	q->next_sched = NULL;
	////ÔÚnet_dev_initÖĞ£¬sd->output_queue_tailp = &sd->output_queue;ËùÒÔÏàµ±ÓÚ°ÑqÌí¼Óµ½ÁËoutput_queue¶ÓÁĞÖĞ
	*sd->output_queue_tailp = q;
	sd->output_queue_tailp = &q->next_sched;
	raise_softirq_irqoff(NET_TX_SOFTIRQ); //¼¤»î·¢ËÍÈí¼şÖĞµÄ£¬×îÖÕµ÷ÓÃnet_tx_action
	local_irq_restore(flags);
}

/*
  * ¼¤»îÊı¾İ°üÊä³öÈíÖĞ¶ÏÓĞ¶à¸ö½Ó¿Ú£¬¶ø
  * __netif_schedule()ÊÇ×î³£ÓÃµÄ¡£
  *///¼¤»î·¢ËÍÈí¼şÖĞµÄ£¬×îÖÕµ÷ÓÃnet_tx_action
void __netif_schedule(struct Qdisc *q)
{
	/*
	  * Èç¹ûÊä³öÍøÂçÉè±¸Ã»ÓĞ´¦ÓÚÁ÷Á¿
	  * ¿ØÖÆµÄµ÷¶ÈÖĞ£¬Ôòµ÷ÓÃ__netif_reschedule()
	  * ¼¤»îÊä³öÈíÖĞ¶Ï
	  */
	if (!test_and_set_bit(__QDISC_STATE_SCHED, &q->state))
		__netif_reschedule(q);
}

void __netif_schedule(struct Qdisc *q)
{
	if (!test_and_set_bit(__QDISC_STATE_SCHED, &q->state))
		__netif_reschedule(q);
}
EXPORT_SYMBOL(__netif_schedule);

void dev_kfree_skb_irq(struct sk_buff *skb)
{
	if (atomic_dec_and_test(&skb->users)) {
		struct softnet_data *sd;
		unsigned long flags;

		local_irq_save(flags);
		sd = &__get_cpu_var(softnet_data);
		skb->next = sd->completion_queue;
		sd->completion_queue = skb;
		raise_softirq_irqoff(NET_TX_SOFTIRQ);
		local_irq_restore(flags);
	}
}
EXPORT_SYMBOL(dev_kfree_skb_irq);

void dev_kfree_skb_any(struct sk_buff *skb)
{
	if (in_irq() || irqs_disabled())
		dev_kfree_skb_irq(skb);
	else
		dev_kfree_skb(skb);
}
EXPORT_SYMBOL(dev_kfree_skb_any);


/**
 * netif_device_detach - mark device as removed
 * @dev: network device
 *
 * Mark device as removed from system and therefore no longer available.
 */
void netif_device_detach(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
		netif_tx_stop_all_queues(dev);
	}
}
EXPORT_SYMBOL(netif_device_detach);

/**
 * netif_device_attach - mark device as attached
 * @dev: network device
 *
 * Mark device as attached from system and restart if needed.
 */
void netif_device_attach(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_PRESENT, &dev->state) &&
	    netif_running(dev)) {
		netif_tx_wake_all_queues(dev);
		__netdev_watchdog_up(dev);
	}
}
EXPORT_SYMBOL(netif_device_attach);

static bool can_checksum_protocol(unsigned long features, __be16 protocol)
{
	return ((features & NETIF_F_NO_CSUM) ||
		((features & NETIF_F_V4_CSUM) &&
		 protocol == htons(ETH_P_IP)) ||
		((features & NETIF_F_V6_CSUM) &&
		 protocol == htons(ETH_P_IPV6)) ||
		((features & NETIF_F_FCOE_CRC) &&
		 protocol == htons(ETH_P_FCOE)));
}

static bool dev_can_checksum(struct net_device *dev, struct sk_buff *skb)
{
	if (can_checksum_protocol(dev->features, skb->protocol))
		return true;

	if (skb->protocol == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veh = (struct vlan_ethhdr *)skb->data;
		if (can_checksum_protocol(dev->features & dev->vlan_features,
					  veh->h_vlan_encapsulated_proto))
			return true;
	}

	return false;
}

/**
 * skb_dev_set -- assign a new device to a buffer
 * @skb: buffer for the new device
 * @dev: network device
 *
 * If an skb is owned by a device already, we have to reset
 * all data private to the namespace a device belongs to
 * before assigning it a new device.
 */
#ifdef CONFIG_NET_NS
void skb_set_dev(struct sk_buff *skb, struct net_device *dev)
{
	skb_dst_drop(skb);
	if (skb->dev && !net_eq(dev_net(skb->dev), dev_net(dev))) {
		secpath_reset(skb);
		nf_reset(skb);
		skb_init_secmark(skb);
		skb->mark = 0;
		skb->priority = 0;
		skb->nf_trace = 0;
		skb->ipvs_property = 0;
#ifdef CONFIG_NET_SCHED
		skb->tc_index = 0;
#endif
	}
	skb->dev = dev;
}
EXPORT_SYMBOL(skb_set_dev);
#endif /* CONFIG_NET_NS */

/*
 * Invalidate hardware checksum when packet is to be mangled, and
 * complete checksum manually on outgoing path.
 */
int skb_checksum_help(struct sk_buff *skb)
{
	__wsum csum;
	int ret = 0, offset;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		goto out_set_summed;

	if (unlikely(skb_shinfo(skb)->gso_size)) {
		/* Let GSO fix up the checksum. */
		goto out_set_summed;
	}

	offset = skb->csum_start - skb_headroom(skb);
	BUG_ON(offset >= skb_headlen(skb));
	csum = skb_checksum(skb, offset, skb->len - offset, 0);

	offset += skb->csum_offset;
	BUG_ON(offset + sizeof(__sum16) > skb_headlen(skb));

	if (skb_cloned(skb) &&
	    !skb_clone_writable(skb, offset + sizeof(__sum16))) {
		ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (ret)
			goto out;
	}

	*(__sum16 *)(skb->data + offset) = csum_fold(csum);
out_set_summed:
	skb->ip_summed = CHECKSUM_NONE;
out:
	return ret;
}
EXPORT_SYMBOL(skb_checksum_help);

/**
 *	skb_gso_segment - Perform segmentation on skb.
 *	@skb: buffer to segment
 *	@features: features for the output path (see dev->features)
 *
 *	This function segments the given skb and returns a list of segments.
 *
 *	It may return NULL if the skb requires no segmentation.  This is
 *	only possible when GSO is used for verifying header integrity.
 */
/*
 * skb_gso_segment()µÄ×÷ÓÃÊÇ·Ö¶ÎGSO¶Î£¬·µ»ØÍ¨¹ıskb->nextÁ´½ÓÔÚÒ»Æğ
 * µÄ¶Î£¬Èç¹û·µ»ØNULL£¬Ôò±íÊ¾GSO¶ÎÃ»ÓĞ½øĞĞ·Ö¶Î£¬²ÎÊıËµÃ÷ÈçÏÂ£º
 * @skb£¬´ı·Ö¸îµÄGSOÊı¾İ°ü
 * @features£¬Êä³öÍøÂçÉè±¸Ö§³ÖµÄGSOÌØĞÔ
 */
struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EPROTONOSUPPORT);
	struct packet_type *ptype;
	__be16 type = skb->protocol;
	int err;

    /*
     * ÔÚGSOÈí·Ö¶ÎÖ®Ç°£¬ÏÈÈ¥µôÒÔÌ«ÍøÖ¡Ê×²¿
     */
	skb_reset_mac_header(skb);
	skb->mac_len = skb->network_header - skb->mac_header;
	__skb_pull(skb, skb->mac_len);

    /*
     * Èç¹û´ı·Ö¸îµÄSKB°üÊÇ¿ËÂ¡µÄ£¬ÔòĞèÖØĞÂ·ÖÅäSKBµÄ
     * ÏßĞÔÊı¾İÇø
     */
	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
		struct net_device *dev = skb->dev;
		struct ethtool_drvinfo info = {};

		if (dev && dev->ethtool_ops && dev->ethtool_ops->get_drvinfo)
			dev->ethtool_ops->get_drvinfo(dev, &info);

		WARN(1, "%s: caps=(0x%lx, 0x%lx) len=%d data_len=%d "
			"ip_summed=%d",
		     info.driver, dev ? dev->features : 0L,
		     skb->sk ? skb->sk->sk_route_caps : 0L,
		     skb->len, skb->data_len, skb->ip_summed);

		if (skb_header_cloned(skb) &&
		    (err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
			return ERR_PTR(err);
	}

    /*
     * ¸ù¾İÊä³ö±¨ÎÄµÄĞ­ÒéÀàĞÍ²éÕÒÓëÖ®¶ÔÓ¦µÄGSO½Ó¿Ú¡£Èç¹ûÖ§³Ö
     * GSO½Ó¿Ú£¬ÔòÈ¥µôIPÊ×²¿£¬È»ºóÔÙµ÷ÓÃgso_segment½Ó¿Ú¶Ô
     * ´ó¶Î½øĞĞ·Ö¸î£¬·µ»ØÏàÓ¦´íÎóÂë
     */
	rcu_read_lock();
	list_for_each_entry_rcu(ptype,
			&ptype_base[ntohs(type) & PTYPE_HASH_MASK], list) { //Èç¹ûÊÇIPV4°ü£¬ÕâÀïÎª²Î¿¼ip_packet_type
		if (ptype->type == type && !ptype->dev && ptype->gso_segment) {
			if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL)) {
				err = ptype->gso_send_check(skb);
				segs = ERR_PTR(err);
				if (err || skb_gso_ok(skb, features))
					break;
				__skb_push(skb, (skb->data -
						 skb_network_header(skb)));
			}
			segs = ptype->gso_segment(skb, features);//inet_gso_segment
			break;
		}
	}
	rcu_read_unlock();

    /*
     * ÎŞÂÛÊÇ·ñÍê³ÉGSO·Ö¶Î£¬×îÖÕ¶¼ĞèÖØĞÂÌí¼ÓÒÔÌ«ÍøÖ¡Ê×²¿
     */
	__skb_push(skb, skb->data - skb_mac_header(skb));

    /*
     * ·µ»ØÏàÓ¦´íÎóÂë
     */
	return segs;
}
EXPORT_SYMBOL(skb_gso_segment);

/* Take action when hardware reception checksum errors are detected. */
#ifdef CONFIG_BUG
void netdev_rx_csum_fault(struct net_device *dev)
{
	if (net_ratelimit()) {
		printk(KERN_ERR "%s: hw csum failure.\n",
			dev ? dev->name : "<unknown>");
		dump_stack();
	}
}
EXPORT_SYMBOL(netdev_rx_csum_fault);
#endif

/* Actually, we should eliminate this check as soon as we know, that:
 * 1. IOMMU is present and allows to map all the memory.
 * 2. No high memory really exists on this machine.
 */

static int illegal_highdma(struct net_device *dev, struct sk_buff *skb)
{
#ifdef CONFIG_HIGHMEM
	int i;
	if (!(dev->features & NETIF_F_HIGHDMA)) {
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
			if (PageHighMem(skb_shinfo(skb)->frags[i].page))
				return 1;
	}

	if (PCI_DMA_BUS_IS_PHYS) {
		struct device *pdev = dev->dev.parent;

		if (!pdev)
			return 0;
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			dma_addr_t addr = page_to_phys(skb_shinfo(skb)->frags[i].page);
			if (!pdev->dma_mask || addr + PAGE_SIZE - 1 > *pdev->dma_mask)
				return 1;
		}
	}
#endif
	return 0;
}

/*
 * GSO¶Î¾­·Ö¶ÎºóËùµÃµ½µÄ¶ÎÍ¨¹ıskb->nextÁ´½ÓÔÚÒ»Æğ¡£µ±ÊÍ·Å
 * GSO¶ÎµÄÊ±ºò£¬ĞèÒª½«ÕâĞ©Á´½ÓÔÚÒ»ÆğµÄ¶ÎÍ¬Ê±ÊÍ·Å£¬Îª´ËĞèÒª
 * Ò»¸öÌØ¶¨µÄ·Ö¶ÎGSO¶ÎÎö¹¹º¯Êı---dev_gso_skb_destructor()
 * ¶øÔ­ÏÈµÄÎö¹¹º¯ÊıĞè½«Æä±£´æÔÚSKBÖĞ×÷ÎªGSO¿ØÖÆ¿éµÄ
 * dev_gso_cb½á¹¹ÖĞ¡£
 */
struct dev_gso_cb {
	void (*destructor)(struct sk_buff *skb);
};

#define DEV_GSO_CB(skb) ((struct dev_gso_cb *)(skb)->cb)

//gso·Ö¶Î¼ûdev_queue_xmit->dev_gso_segment
static void dev_gso_skb_destructor(struct sk_buff *skb)
{
	struct dev_gso_cb *cb;

    /*
     * É¾³ı²¢ÊÍ·Å³ıµÚÒ»¸öÖ®ÍâµÄSKB
     */
	do {
		struct sk_buff *nskb = skb->next;

		skb->next = nskb->next;
		nskb->next = NULL;
		kfree_skb(nskb);
	} while (skb->next);

    /*
     * ×îºóµ÷ÓÃÔ­ÏÈµÄÎö¹¹º¯ÊıÊÍ·ÅµÚÒ»¸öSKB
     */
	cb = DEV_GSO_CB(skb);
	if (cb->destructor)
		cb->destructor(skb);
}


/**
 *	dev_gso_segment - Perform emulated hardware segmentation on skb.
 *	@skb: buffer to segment
 *
 *	This function segments the given skb and stores the list of segments
 *	in skb->next.
 */
/*
 * dev_gso_segment()Í¨¹ıµ÷ÓÃskb_gso_segment()À´·Ö¸îGSO¶Î
 *///ÕâÀïµÄÊı¾İÊ±¾­¹ı__skb_linearizeÀ­Ö±µÄÊı¾İ
static int dev_gso_segment(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct sk_buff *segs;
    /*
     * »ñÈ¡Êä³öÍøÂçÉè±¸µÄ¾ÛºÏ·ÖÉ¢I/OÌØĞÔ
     */
	int features = dev->features & ~(illegal_highdma(dev, skb) ?
					 NETIF_F_SG : 0);

    /*
     * ¸ù¾İÊä³öÍøÂçÉè±¸µÄ¾ÛºÏ·ÖÉ¢I/OÌØĞÔ£¬¶Ô¶Î½øĞĞÈíGSO·Ö¶Î£¬
     * ·Ö¸îºóµÃµ½µÄ¶ÎÍ¨¹ıskb->nextÁ´½ÓÔÚÒ»Æğ¡£
     */
	segs = skb_gso_segment(skb, features);

	/* Verifying header integrity only. */
	if (!segs)
		return 0;

	if (IS_ERR(segs))
		return PTR_ERR(segs);

    /*
     * ·Ö¶Î³É¹¦ºó£¬Ğè±£´æSKBÔ­À´µÄÎö¹¹º¯Êı£¬È»ºóÖØĞÂÉèÖÃ
     * ÎªÌØ¶¨µÄ·Ö¶ÎGSO¶ÎÎö¹¹º¯Êıdev_gso_skb_destrutor().
     */
	skb->next = segs;
	DEV_GSO_CB(skb)->destructor = skb->destructor;
	skb->destructor = dev_gso_skb_destructor;

	return 0;
}

/*
 * Try to orphan skb early, right before transmission by the device.
 * We cannot orphan skb if tx timestamp is requested, since
 * drivers need to call skb_tstamp_tx() to send the timestamp.
 */
static inline void skb_orphan_try(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	if (sk && !skb_tx(skb)->flags) {
		/* skb_tx_hash() wont be able to get sk.
		 * We copy sk_hash into skb->rxhash
		 */
		if (!skb->rxhash)
			skb->rxhash = sk->sk_hash;
		skb_orphan(skb);
	}
}

/*
  * dev_hard_start_xmit()½«´ıÊä³öµÄÊı¾İ°üÌá½»¸øÍøÂçÉè±¸µÄ
  * Êä³ö½Ó¿Ú£¬Íê³ÉÊı¾İ°üµÄÊä³ö¡£
  */ //×ßµ½ÕâÀïµÄSKB,Í¨¹ıip_local_out×ßµ½ÕâÀï,×ßµ½ÕâÀïµÄSKBÔÚip_local_outÖĞÒÑ¾­°ÑIP²ã¼°ÆäÒÔÉÏ¸÷²ãÒÑ¾­·â×°Íê±Ï¡£¸Ãº¯Êıºó¿ªÊ¼×ß¶ş²ã·â×°
int dev_hard_start_xmit(struct sk_buff *skb, struct net_device *dev,
			struct netdev_queue *txq)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int rc;

	/*
	  * Èç¹ûÊä³öÊÇµ¥¸öÊı¾İ°ü£¬Í¨³£Çé¿öÏÂ¶¼ÊÇ
	  * Êä³öµ¥¶ÀÊı¾İ°ü¡£
	  */
	if (likely(!skb->next)) {
		/*
		  * Èç¹ûÓ¦ÓÃ²ãÍ¨¹ısocket(AF_PACKET£¬SOCK_RAW£¬htons(ETH_P_ALL))
		  * ´´½¨µÄÔ­Ê¼Ì×½Ó×Ö£¬ÔòĞè·¢ËÍÒ»·İÊı¾İ°ü¸øÕâÑù
		  * µÄÌ×½Ó×Ö¡£
		  */
		if (!list_empty(&ptype_all))
			dev_queue_xmit_nit(skb, dev);

		/*
		  * Èç¹û´ıÊä³öÊı¾İ°üÊÇGSOÊı¾İ°ü£¬µ«ÍøÂçÉè±¸
		  * ²»Ö§³ÖÏàÓ¦µÄÌØĞÔ£¬Ôòµ÷ÓÃdev_gso_segment()¶Ô
		  * GSOÊı¾İ°ü½øĞĞÈí·Ö¸î¡£Èç¹û¾­·Ö¸îºóÈÔÊÇ
		  * Ò»¸öÊı¾İ°ü£¬ÔòÖ±½Óµ÷ÓÃÍøÂçÉè±¸µÄhard_start_xmit
		  * ½Ó¿ÚÊä³öÊı¾İ°ü¡£È»¶ø£¬Í¨³£Ò»¸öGSOÊı¾İ°ü¾­
		  * Èí·Ö¸î£¬»áÉú³É¶à¸öÁ´½ÓÆğÀ´µÄÊı¾İ°ü£¬Èç¹û
		  * ÊÇÕâÑùµÄ»°¾ÍĞèÌø×ªµ½gso±êÇ©´¦£¬Öğ¸ö´¦Àí
		  * Êı¾İ°ü¡£
		  */ //¼ûdev_gso_segment
		if (netif_needs_gso(dev, skb)) {
			if (unlikely(dev_gso_segment(skb)))
				goto out_kfree_skb;
			if (skb->next)
				goto gso;
		}

		/*
		 * If device doesnt need skb->dst, release it right now while
		 * its hot in this cpu cache
		 */
		if (dev->priv_flags & IFF_XMIT_DST_RELEASE)
			skb_dst_drop(skb);

		/*
		 * e1000ÍøÂçÉè±¸Çı¶¯ÖĞÎªe1000_xmit_frame()
		 */
		rc = ops->ndo_start_xmit(skb, dev); //ÔÚ¸Ãº¯ÊıÖĞ·â×°MAC²ã
		if (rc == NETDEV_TX_OK)
			txq_trans_update(txq);
		/*
		 * TODO: if skb_orphan() was called by
		 * dev->hard_start_xmit() (for example, the unmodified
		 * igb driver does that; bnx2 doesn't), then
		 * skb_tx_software_timestamp() will be unable to send
		 * back the time stamp.
		 *
		 * How can this be prevented? Always create another
		 * reference to the socket before calling
		 * dev->hard_start_xmit()? Prevent that skb_orphan()
		 * does anything in dev->hard_start_xmit() by clearing
		 * the skb destructor before the call and restoring it
		 * afterwards, then doing the skb_orphan() ourselves?
		 */
		return rc;
	}

gso:
	/*
	  * µ±Ò»¸öGSOÊı¾İ°ü¾­¹ıÈí·Ö¸î£¬Éú³É
	  * ¶à¸öÁ´½ÓÆğÀ´µÄÊı¾İ°üºó£¬ĞèÖğ¸ö
	  * ´¦ÀíÊı¾İ°ü¡£µ÷ÓÃÍøÂçÉè±¸µÄndo_start_xmit
	  * ½Ó¿Ú(e100ÍøÂçÉè±¸Çı¶¯ÖĞÎªe100_xmit_frame())
	  * Êä³öÊı¾İ°ü£¬Èç¹û·¢Éú´íÎó£¬Ôò·µ»Ø
	  * ÏàÓ¦´íÎóÂë¡£
	  */
	do {
		struct sk_buff *nskb = skb->next;

		skb->next = nskb->next;
		nskb->next = NULL;
		rc = ops->ndo_start_xmit(nskb, dev);
		if (unlikely(rc != NETDEV_TX_OK)) {
			nskb->next = skb->next;
			skb->next = nskb;
			return rc;
		}
		txq_trans_update(txq);
		if (unlikely(netif_tx_queue_stopped(txq) && skb->next))
			return NETDEV_TX_BUSY;
	} while (skb->next);

	/*
	  * ³É¹¦·¢ËÍÁËËùÓĞµÄÊı¾İ°ü£¬Ğè»Ö¸´
	  * SKBÔ­ÏÈµÄÎö¹¹º¯Êı¡£
	  */
	skb->destructor = DEV_GSO_CB(skb)->destructor;

/*
  * Èç¹ûµ÷ÓÃdev_gso_segment()¶ÔGSOÊı¾İ°ü½øĞĞ
  * Èí·Ö¸îÊ§°Ü£¬»áÌø×ªµ½´Ë¶ªÆúÊı¾İ°ü¡£
  */
out_kfree_skb:
	kfree_skb(skb);
	return NETDEV_TX_OK;
}

static u32 hashrnd __read_mostly;

u16 skb_tx_hash(const struct net_device *dev, const struct sk_buff *skb)
{
	u32 hash;

	if (skb_rx_queue_recorded(skb)) {
		hash = skb_get_rx_queue(skb);
		while (unlikely(hash >= dev->real_num_tx_queues))
			hash -= dev->real_num_tx_queues;
		return hash;
	}

	if (skb->sk && skb->sk->sk_hash)
		hash = skb->sk->sk_hash;
	else
		hash = (__force u16) skb->protocol ^ skb->rxhash;
	hash = jhash_1word(hash, hashrnd);

	return (u16) (((u64) hash * dev->real_num_tx_queues) >> 32);
}
EXPORT_SYMBOL(skb_tx_hash);

static inline u16 dev_cap_txqueue(struct net_device *dev, u16 queue_index)
{
	if (unlikely(queue_index >= dev->real_num_tx_queues)) {
		if (net_ratelimit()) {
			pr_warning("%s selects TX queue %d, but "
				"real number of TX queues is %d\n",
				dev->name, queue_index, dev->real_num_tx_queues);
		}
		return 0;
	}
	return queue_index;
}

/*
//Ñ¡ÔñÒ»¸ö·¢ËÍ¶ÓÁĞ£¬Èç¹ûÉè±¸Ìá¹©ÁËselect_queue»Øµ÷º¯Êı¾ÍÊ¹ÓÃËü£¬·ñÔòÓÉÄÚºËÑ¡ÔñÒ»¸ö¶ÓÁĞ     
//´ó²¿·ÖÇı¶¯¶¼²»»áÉèÖÃ¶à¸ö¶ÓÁĞ£¬¶øÊÇÔÚµ÷ÓÃalloc_etherdev·ÖÅänet_deviceÊ±½«¶ÓÁĞ¸öÊıÉèÖÃÎª1     
//Ò²¾ÍÊÇÖ»ÓĞÒ»¸ö¶ÓÁĞ 
*/
static struct netdev_queue *dev_pick_tx(struct net_device *dev,
					struct sk_buff *skb)
{
	int queue_index;
	struct sock *sk = skb->sk;

	queue_index = sk_tx_queue_get(sk);
	if (queue_index < 0) {
		const struct net_device_ops *ops = dev->netdev_ops;

		if (ops->ndo_select_queue) {
			queue_index = ops->ndo_select_queue(dev, skb);
			queue_index = dev_cap_txqueue(dev, queue_index);
		} else {
			queue_index = 0;
			if (dev->real_num_tx_queues > 1)
				queue_index = skb_tx_hash(dev, skb);

			if (sk) {
				struct dst_entry *dst = rcu_dereference_check(sk->sk_dst_cache, 1);

				if (dst && skb_dst(skb) == dst)
					sk_tx_queue_set(sk, queue_index);
			}
		}
	}

	skb_set_queue_mapping(skb, queue_index);
	return netdev_get_tx_queue(dev, queue_index);
}

static inline int __dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
				 struct net_device *dev,
				 struct netdev_queue *txq)
{
	spinlock_t *root_lock = qdisc_lock(q);
	int rc;

	spin_lock(root_lock);
	if (unlikely(test_bit(__QDISC_STATE_DEACTIVATED, &q->state))) {
		kfree_skb(skb);//Èç¹ûÕâ¸ö¶ÓÁĞÊÇÎ´ÔËĞĞµÄ£¬ÄÇÃ´ÊÍ·ÅÕâ¸öÊı¾İ°ü
		rc = NET_XMIT_DROP;
	} else if ((q->flags & TCQ_F_CAN_BYPASS) && !qdisc_qlen(q) &&
		   !test_and_set_bit(__QDISC_STATE_RUNNING, &q->state)) {
		/* //Èç¹ûÒ»¸ö¶ÓÁĞÊÇÎ»ÔËĞĞµÄ£¬ËµÃ÷Õâ¸ö¶ÓÁĞÀïÃæÃ»ÓĞÊı¾İ°ü£¬´ËÊ±¿ÉÒÔÖ±½Ó·¢ËÍÕâ¸ö°ü
		 * This is a work-conserving queue; there are no old skbs
		 * waiting to be sent out; and the qdisc is not running -
		 * xmit the skb directly.
		 */
		if (!(dev->priv_flags & IFF_XMIT_DST_RELEASE))
			skb_dst_force(skb);
		__qdisc_update_bstats(q, skb->len);
		if (sch_direct_xmit(skb, q, dev, txq, root_lock))
			__qdisc_run(q);//ÊÔÍ¼Ö±½Ó·¢ËÍÊı¾İ°ü£¬Èç¹ûÃ»ÓĞ·¢ËÍ³É¹¦£¬»òÕß¶ÓÁĞÖĞ»¹ÓĞ´ı·¢Êı¾İ°ü£¬·µ»ØÖµ»á´óÓÚ0£¬ÄÇÃ´£¬´ËÊ±ĞèÒª¼¤»îÕâ¸ö¶ÓÁĞ¡£
		else
			clear_bit(__QDISC_STATE_RUNNING, &q->state);

		rc = NET_XMIT_SUCCESS;
	} else {//Èç¹ûÒÑ¾­ÓĞCPUÔÚÔËĞĞÕâ¸ö¶ÓÁĞ£¬ÄÇÃ´×Ö½Ú·µ»Ø£¬ÒòÎªÒ»¸ö¶ÓÁĞÖ»ÄÜÓÉÒ»¸öCPUÔËĞĞ¡£ÔòÖ±½Ó°ÑSKBÈë¶Ó
		skb_dst_force(skb);
		rc = qdisc_enqueue_root(skb, q);//ÔòÖ±½Ó°ÑSKBÈë¶Ó,²Î¿¼pfifo_qdisc_ops
		qdisc_run(q);
	}
	spin_unlock(root_lock);

	return rc;
}

/*
 * Returns true if either:
 *	1. skb has frag_list and the device doesn't support FRAGLIST, or
 *	2. skb is fragmented and the device does not support SG, or if
 *	   at least one of fragments is in highmem and device does not
 *	   support DMA from it.
 */
static inline int skb_needs_linearize(struct sk_buff *skb,
				      struct net_device *dev)
{
	return (skb_has_frags(skb) && !(dev->features & NETIF_F_FRAGLIST)) ||
	       (skb_shinfo(skb)->nr_frags && (!(dev->features & NETIF_F_SG) ||
					      illegal_highdma(dev, skb)));
}

static DEFINE_PER_CPU(int, xmit_recursion);
#define RECURSION_LIMIT 10

/**
 *	dev_queue_xmit - transmit a buffer
 *	@skb: buffer to transmit
 *
 *	Queue a buffer for transmission to a network device. The caller must
 *	have set the device and priority and built the buffer before calling
 *	this function. The function can be called from an interrupt.
 *
 *	A negative errno code is returned on a failure. A success does not
 *	guarantee the frame will be transmitted as it may be dropped due
 *	to congestion or traffic shaping.
 *
 * -----------------------------------------------------------------------------------
 *      I notice this method can also return errors from the queue disciplines,
 *      including NET_XMIT_DROP, which is a positive value.  So, errors can also
 *      be positive.
 *
 *      Regardless of the return value, the skb is consumed, so it is currently
 *      difficult to retry a send to this method.  (You can bump the ref count
 *      before sending to hold a reference for retry if you are careful.)
 *
 *      When calling this method, interrupts MUST be enabled.  This is because
 *      the BH enable code must have IRQs enabled so that it will not deadlock.
 *          --BLG
 Ğ­ÒéÕ»ÏòÉè±¸·¢ËÍÊı¾İ°üÊ±¶¼Ğèµ÷ÓÃ¸Ãº¯Êı£¬¸Ãº¯Êı¶ÔSKB½øĞĞÅÅ¶Ó£¬×îÖÕÓÉµ×²ãÉè±¸Çı¶¯³ÌĞò½øĞĞ´«Êä
 */
    
    /**
     *  dev_queue_xmit - transmit a buffer
     *  @skb: buffer to transmit
     *
     *  Queue a buffer for transmission to a network device. The caller must
     *  have set the device and priority and built the buffer before calling
     *  this function. The function can be called from an interrupt.
     *
     *  A negative errno code is returned on a failure. A success does not
     *  guarantee the frame will be transmitted as it may be dropped due
     *  to congestion or traffic shaping.
     *
     * -----------------------------------------------------------------------------------
     *      I notice this method can also return errors from the queue disciplines,
     *      including NET_XMIT_DROP, which is a positive value.  So, errors can also
     *      be positive.
     *
     *      Regardless of the return value, the skb is consumed, so it is currently
     *      difficult to retry a send to this method.  (You can bump the ref count
     *      before sending to hold a reference for retry if you are careful.)
     *
     *      When calling this method, interrupts MUST be enabled.  This is because
     *      the BH enable code must have IRQs enabled so that it will not deadlock.
     *          --BLG
     */
 /*
  * ÍøÂç½Ó¿Ú¿ÚºËĞÄ²ãÏòÍøÂçĞ­Òé²ãÌá¹©µÄÍ³Ò»
  * µÄ·¢ËÍ½Ó¿Ú£¬ÎŞÂÛIP£¬»¹ÊÇARPĞ­Òé£¬ÒÔ¼°ÆäËü
  * ¸÷ÖÖµ×²ãĞ­Òé£¬Í¨¹ıÕâ¸öº¯Êı°ÑÒª·¢ËÍµÄÊı¾İ
  * ´«µİ¸øÍøÂç½Ó¿ÚºËĞÄ²ã
  * 
  * update:
  *   ÈôÖ§³ÖÁ÷Á¿¿ØÖÆ£¬Ôò½«´ıÊä³öµÄÊı¾İ°ü¸ù¾İ¹æÔò
  * ¼ÓÈëµ½Êä³öÍøÂç¶ÓÁĞÖĞÅÅ¶Ó£¬²¢ÔÚºÏÊÊµÄÊ±»ú¼¤»î
  * ÍøÂçÉè±¸Êä³öÈíÖĞ¶Ï£¬ÒÀ´Î½«±¨ÎÄ´Ó¶ÓÁĞÖĞÈ¡³öÍ¨¹ı
  * ÍøÂçÉè±¸Êä³ö¡£Èô²»Ö§³ÖÁ÷Á¿¿ØÖÆ£¬ÔòÖ±½Ó½«Êı¾İ°ü
  * ´ÓÍøÂçÉè±¸Êä³ö¡£
  *   Èç¹ûÌá½»Ê§°Ü£¬Ôò·µ»ØÏàÓ¦µÄ´íÎóÂë£¬È»¶ø·µ»Ø
  * ³É¹¦Ò²²¢²»ÄÜÈ·±£Êı¾İ°ü±»³É¹¦·¢ËÍ£¬ÒòÎªÓĞ¿ÉÄÜ
  * ÓÉÓÚÓµÈû¶øµ¼ÖÂÁ÷Á¿¿ØÖÆ»úÖÆ½«Êı¾İ°ü¶ªÆú¡£
  *   µ÷ÓÃdev_queue_xmit()º¯ÊıÊä³öÊı¾İ°ü£¬Ç°ÌáÊÇ±ØĞëÆôÓÃ
  * ÖĞ¶Ï£¬Ö»ÓĞÆôÓÃÖĞ¶ÏÖ®ºó²ÅÄÜ¼¤»îÏÂ°ë²¿¡£
  */ //µ½ÕâÀïµÄskb¿ÉÄÜÓĞÒÔÏÂÈıÖÖ:Ö§³ÖGSO(FRAGLISTÀàĞÍµÄ¾ÛºÏ·ÖÉ¢I/OÊı¾İ°ü, ¶ÔÓÚSGÀàĞÍµÄ¾ÛºÏ·ÖÉ¢I/OÊı¾İ°ü), »òÕßÊÇ·ÇGSOµÄSKB£¬µ«ÕâÀïµÄskbÊÇÔÚip_finish_outputÖĞ·ÖÆ¬ºóµÄskb
int dev_queue_xmit(struct sk_buff *skb) //Í¨¹ıip_local_out×ßµ½ÕâÀï,×ßµ½ÕâÀïµÄSKBÆğIP²ã¼°ÆäÒÔÉÏ¸÷²ãÒÑ¾­·â×°Íê±Ï¡£
{
    struct net_device *dev = skb->dev;
    struct netdev_queue *txq;
    struct Qdisc *q;
    int rc = -ENOMEM;

    /* GSO will handle the following emulations directly. */
    /*
      * Èç¹ûÊÇGSOÊı¾İ°ü£¬ÇÒÍøÂçÉè±¸Ö§³Ö
      * GSOÊı¾İ°üµÄ´¦Àí£¬ÔòÌø×ªµ½
      * gso±êÇ©´¦¶ÔGSOÊı¾İ°üÖ±½Ó´¦Àí¡£
      */
    if (netif_needs_gso(dev, skb))
        goto gso;

    /*
      * ¶ÔÓÚFRAGLISTÀàĞÍµÄ¾ÛºÏ·ÖÉ¢I/OÊı¾İ°ü£¬
      * Èç¹ûÊä³öÍøÂçÉè±¸²»Ö§³ÖFRAGLISTÀàĞÍµÄ
      * ¾ÛºÏ·ÖÉ¢I/O(Ä¿Ç°Ö»ÓĞ»Ø»·Éè±¸Ö§³Ö)£¬
      * ÔòĞè½«ÆäÏßĞÔ»¯¡£ÈôÏßĞÔ»¯Ê§°Ü£¬Ôò
      * ¶ªÆúÊı¾İ°ü£¬·¢ËÍÊ§°Ü¡£
      //Èç¹û·¢ËÍµÄÊı¾İ°üÊÇ·ÖÆ¬ µ«Íø¿¨²»Ö§³ÖskbµÄËéÆ¬ÁĞ±í,ÔòĞèÒªµ÷ÓÃº¯Êı__skb_linearize°ÑÕâĞ©ËéÆ¬ÖØ×éµ½Ò»¸öÍêÕûµÄskbÖĞ
      */
    if (skb_has_frags(skb) &&
        !(dev->features & NETIF_F_FRAGLIST) &&
        __skb_linearize(skb))
        goto out_kfree_skb;

    /* Fragmented skb is linearized if device does not support SG,
     * or if at least one of fragments is in highmem and device
     * does not support DMA from it.
     */
    /*
      * ¶ÔÓÚSGÀàĞÍµÄ¾ÛºÏ·ÖÉ¢I/OÊı¾İ°ü£¬Èç¹û
      * Êä³öÍøÂçÉè±¸²»Ö§³ÖSGÀàĞÍµÄ¾ÛºÏ·ÖÉ¢I/O£¬
      * ÔòĞè½«ÆäÏßĞÔ»¯¡£Èç¹ûÍøÂçÉè±¸²»Ö§³Ö
      * ÔÚ¸ß¶ËÄÚ´æÊ¹ÓÃDMA£¬µ«¸ß¶ËÄÚ´æÖĞÓĞ·ÖÆ¬£¬
      * ´ËÊ±Ò²ĞèÒª½«Êı¾İ°üÏßĞÔ»¯¡£ÈôÏßĞÔ»¯Ê§°Ü£¬
      * Ôò¶ªÆú¸ÃÊı¾İ°ü£¬·¢ËÍÊ§°Ü¡£
       //Èç¹ûÒª·¢ËÍµÄÊı¾İ°üÊ¹ÓÃÁË·ÖÉ¢/¾ÛºÏi/o µ«Íø¿¨²»Ö§³Ö»ò·ÖÆ¬ÖĞÖÁÉÙÓĞÒ»¸öÔÚ¸ß¶ËÄÚ´æÖĞ,²¢ÇÒÍø¿¨²»Ö§³Ödma,ÔòÍ¬ÑùĞèÒªµ÷ÓÃº¯Êı__skb_linearize
       ½øĞĞÏßĞÔ»¯´¦Àí 
      */
    if (skb_shinfo(skb)->nr_frags &&
        (!(dev->features & NETIF_F_SG) || illegal_highdma(dev, skb)) &&
        __skb_linearize(skb))
        goto out_kfree_skb;

    /* If packet is not checksummed and device does not support
     * checksumming for this protocol, complete checksumming here.
     */
    /*
      * Èç¹û´ıÊä³öµÄÊı¾İ°üÓÉÓ²¼şÀ´Ö´ĞĞĞ£ÑéºÍ
      * (ÉĞÎ´Ö´ĞĞĞ£ÑéºÍ)£¬µ«ÍøÂçÉè±¸²»Ö§³Ö
      * Ó²¼şÖ´ĞĞĞ£ÑéºÍ£¬²»Ö§³Ö¶ÔIP±¨ÎÄÖ´ĞĞ
      * Ğ£ÑéºÍ£¬ÔòÔÚ´Ë´¦¼ÆËãĞ£ÑéºÍ¡£Èô
      * Ğ£ÑéºÍÊ§°Ü£¬Ôò¶ªÆúÊı¾İ°ü£¬·¢ËÍÊ§°Ü¡£
      */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        skb_set_transport_header(skb, skb->csum_start -
                          skb_headroom(skb));
        if (!dev_can_checksum(dev, skb) && skb_checksum_help(skb))
            goto out_kfree_skb;
    }

gso:
    /* Disable soft irqs for various locks below. Also
     * stops preemption for RCU.
     */
    rcu_read_lock_bh();

    /* »ñÈ¡devÉè±¸ÉÏµÄÅÅ¶Ó¹æ³Ì£¬Èç¹ûÖ´ĞĞÁËtc qdisc add dev eth0 ¾Í»áÕÒµ½¶ÔÓ¦µÄQdisc */
    txq = dev_pick_tx(dev, skb);
    /*
      * »ñÈ¡Êä³öÍøÂçÉè±¸µÄÅÅ¶Ó¹æ³Ì¡£rcu_dereference()ÔÚ
      * RCU¶ÁÁÙ½ç²¿·ÖÖĞÈ¡³öÒ»¸öRCU±£»¤µÄÖ¸Õë¡£ÔÚ
      * ĞèÒªÄÚ´æÆÁÕÏµÄÌåÏµÖĞ½øĞĞÄÚ´æÆÁÕÏ£¬Ä¿Ç°
      * Ö»ÓĞAlphaÌåÏµĞèÒª¡£
      */
    q = rcu_dereference(txq->qdisc); //Êµ¼ÊÉÏ¾ÍÊÇ»ñÈ¡net_device -> netdev_queue  Ò²¾ÍÊÇ¸ÃdevÉè±¸µÄ¸úqdisc

#ifdef CONFIG_NET_CLS_ACT
    /*
      * Óë°ü·ÖÀàÆ÷Ïà¹Ø
      */
    skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_EGRESS);
#endif
    /*
      * Èç¹û»ñÈ¡µÄÅÅ¶Ó¹æ³Ì¶¨ÒåÁË"Èë¶Ó"²Ù×÷£¬
      * ËµÃ÷ÆôÓÃÁËQoS¡£
      */ /*Èç¹ûÕâ¸öÉè±¸Æô¶¯ÁËTC,ÄÇÃ´°ÑÊı¾İ°üÑ¹Èë¶ÓÁĞ  ¼ûtc_modify_qdiscÖĞµÄqdisc_graft*/ 
    if (q->enqueue) {//Ôò¶ÔÕâ¸öÊı¾İ°ü½øĞĞQoS´¦Àí¡£ /* qosÔ´Âë·ÖÎö²Î¿¼<TCÁ÷ËÙÁ÷Á¿¿ØÖÆ·ÖÎö> */  //alloc_netdev_mq¿ÉÒÔ¿´³ö¿ª±ÙµÄqµÄ¿Õ¼äÎª¿ÕµÄ£¬Èç¹û²»¸³ÖµµÄ»°
    //½øÈë³ö¿ÚÁ÷¿ØµÄº¯ÊıÎªdev_queue_xmit(); Èç¹ûÊÇÈë¿ÚÁ÷¿Ø, Êı¾İÖ»ÊÇ¸Õ´ÓÍø¿¨Éè±¸ÖĞÊÕµ½, »¹Î´½»µ½ÍøÂçÉÏ²ã´¦Àí, 
    //²»¹ıÍø¿¨µÄÈë¿ÚÁ÷¿Ø²»ÊÇ±ØĞëµÄ, È±Ê¡Çé¿öÏÂ²¢²»½øĞĞÁ÷¿Ø£¬½øÈëÈë¿ÚÁ÷¿Øº¯ÊıÎªing_filter()º¯Êı£¬¸Ãº¯Êı±»skb_receive_skb()µ÷ÓÃ¡£
        /*
          * ½«´ı·¢ËÍµÄÊı¾İ°ü°´ÅÅ¶Ó¹æÔò²åÈëµ½
          * ¶ÓÁĞ£¬È»ºó½øĞĞÁ÷Á¿¿ØÖÆ£¬µ÷¶È¶ÓÁĞ
          * Êä³öÊı¾İ°ü£¬Íê³Éºó·µ»Ø¡£
          */
        rc = __dev_xmit_skb(skb, q, dev, txq);
        goto out;//Êı¾İ°üÈë¶Óºó£¬Õû¸öÈë¶ÓÁ÷³Ì¾Í½áÊøÁË
    }

    /* The device has no queue. Common case for software devices:
       loopback, all the sorts of tunnels...

       Really, it is unlikely that netif_tx_lock protection is necessary
       here.  (f.e. loopback and IP tunnels are clean ignoring statistics
       counters.)
       However, it is possible, that they rely on protection
       made by us here.

       Check this and shot the lock. It is not prone from deadlocks.
       Either shot noqueue qdisc, it is even simpler 8)
     */
    /*
      * Èç¹ûÉè±¸ÒÑ´ò¿ªµ«Î´ÆôÓÃQoS£¬ÔòÖ±½ÓÊä³ö
      * Êı¾İ°ü¡£
      */
    if (dev->flags & IFF_UP) {
        int cpu = smp_processor_id(); /* ok because BHs are off */

        /*
          * HARD_TX_LOCK/HARD_TX_UNLOCKÊÇÒ»¶Ô²Ù×÷£¬
          * ÔÚÕâÁ½¸ö²Ù×÷Ö®¼ä²»ÄÜÔÙ´Îµ÷ÓÃ
          * dev_queue_xmit½Ó¿Ú¡£Òò´ËÈç¹ûÕıÔÚÓÃ
          * ¸ÃÍøÂçÉè±¸·¢ËÍÊı¾İ°üµÄCPUÓÖ
          * µ÷ÓÃdev_queue_xmit()Êä³öÊı¾İ°ü£¬Ôò
          * ËµÃ÷´úÂëÓĞbug£¬ĞèÊä³ö¾¯¸æĞÅÏ¢¡£
          *   ·ñÔò£¬Ê×ÏÈĞè¼ÓËø£¬ÒÔ·ÀÖ¹ÆäËûCPU
          * µÄ²¢·¢²Ù×÷£¬È»ºóÔÚÍøÂçÉè±¸´¦ÓÚ¿ªÆô
          * ×´Ì¬Ê±£¬µ÷ÓÃdev_hard_start_xmit()Êä³öÊı¾İ°ü
          * µ½ÍøÂçÉè±¸¡£
          */
        if (txq->xmit_lock_owner != cpu) {

            HARD_TX_LOCK(dev, txq, cpu);

            if (!netif_tx_queue_stopped(txq)) {
                rc = NET_XMIT_SUCCESS;
                if (!dev_hard_start_xmit(skb, dev, txq)) {
                    HARD_TX_UNLOCK(dev, txq);
                    goto out;
                }
            }
            HARD_TX_UNLOCK(dev, txq);
            if (net_ratelimit())
                printk(KERN_CRIT "Virtual device %s asks to "
                       "queue packet!\n", dev->name);
        } else {
            /* Recursion is detected! It is possible,
             * unfortunately */
            if (net_ratelimit())
                printk(KERN_CRIT "Dead loop on virtual device "
                       "%s, fix it urgently!\n", dev->name);
        }
    }

    /*
      * Èç¹ûÍøÂçÉè±¸´¦ÓÚ¹Ø±Õ×´Ì¬£¬Ôò·µ»Ø
      * ÏàÓ¦µÄ´íÎóÂë¡£
      */
    rc = -ENETDOWN;
    rcu_read_unlock_bh();

/*
  * ·²Ìø×ªµ½´Ë´¦µÄ¶¼ÊÇÊä³öÊı¾İ°üÊ±³öÏÖ´íÎóµÄ£¬
  * Èç¾ÛºÏ·ÖÉ¢I/OÊı¾İ°üÏßĞÔ»¯Ê§°Ü£¬¶ªÆúÊı¾İ°ü¡£
  */
out_kfree_skb:
    kfree_skb(skb);
    return rc;
out:
    /*
      * Íê³ÉÊı¾İ°üÊä³öºó£¬·µ»ØÏàÓ¦½á¹û¡£
      */
    rcu_read_unlock_bh();
    return rc;
}

int dev_queue_x11mit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	struct Qdisc *q;
	int rc = -ENOMEM;

	/* GSO will handle the following emulations directly. */
	if (netif_needs_gso(dev, skb))
		goto gso;

	/* Convert a paged skb to linear, if required */
	if (skb_needs_linearize(skb, dev) && __skb_linearize(skb))
		goto out_kfree_skb;

	/* If packet is not checksummed and device does not support
	 * checksumming for this protocol, complete checksumming here.
	 */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		skb_set_transport_header(skb, skb->csum_start -
					      skb_headroom(skb));
		if (!dev_can_checksum(dev, skb) && skb_checksum_help(skb))
			goto out_kfree_skb;
	}

gso:
	/* Disable soft irqs for various locks below. Also
	 * stops preemption for RCU.
	 */
	rcu_read_lock_bh();

	txq = dev_pick_tx(dev, skb);
	q = rcu_dereference_bh(txq->qdisc);

#ifdef CONFIG_NET_CLS_ACT
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_EGRESS);
#endif
	if (q->enqueue) {
		rc = __dev_xmit_skb(skb, q, dev, txq);
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	   loopback, all the sorts of tunnels...

	   Really, it is unlikely that netif_tx_lock protection is necessary
	   here.  (f.e. loopback and IP tunnels are clean ignoring statistics
	   counters.)
	   However, it is possible, that they rely on protection
	   made by us here.

	   Check this and shot the lock. It is not prone from deadlocks.
	   Either shot noqueue qdisc, it is even simpler 8)
	 */
	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id(); /* ok because BHs are off */

		if (txq->xmit_lock_owner != cpu) {

			if (__this_cpu_read(xmit_recursion) > RECURSION_LIMIT)
				goto recursion_alert;

			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_tx_queue_stopped(txq)) {
				__this_cpu_inc(xmit_recursion);
				rc = dev_hard_start_xmit(skb, dev, txq);
				__this_cpu_dec(xmit_recursion);
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			if (net_ratelimit())
				printk(KERN_CRIT "Virtual device %s asks to "
				       "queue packet!\n", dev->name);
		} else {
			/* Recursion is detected! It is possible,
			 * unfortunately
			 */
recursion_alert:
			if (net_ratelimit())
				printk(KERN_CRIT "Dead loop on virtual device "
				       "%s, fix it urgently!\n", dev->name);
		}
	}

	rc = -ENETDOWN;
	rcu_read_unlock_bh();

out_kfree_skb:
	kfree_skb(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}
EXPORT_SYMBOL(dev_queue_xmit);


/*=======================================================================
			Receiver routines
  =======================================================================*/

int netdev_max_backlog __read_mostly = 1000;
int netdev_tstamp_prequeue __read_mostly = 1;
int netdev_budget __read_mostly = 300;
int weight_p __read_mostly = 64;            /* old backlog weight */

/* Called with irq disabled */
//ËüµÄ×÷ÓÃ¾ÍÊÇÍø¿¨µÄÊı¾İÁ´±íÌí¼Óµ½poll_listÀï£¬È»ºó¿ªÆôÈíÖĞ¶Ï, º¯Êı__raise_softirq_irqoff×îÖÕ»áµ÷ÓÃwakeup_softirqd(void)¡£
/*ÕâÊÇNAPI·½Ê½£¬°ÑdevÉè±¸Ìí¼Óµ½ÁËpoll_listÁ´±íÖĞ¡£
Ã¿¸öÍøÂçÉè±¸£¨MAC²ã£©¶¼ÓĞ×Ô¼ºµÄnet_deviceÊı¾İ½á¹¹£¬Õâ¸ö½á¹¹ÉÏÓĞnapi_struct¡£Ã¿µ±ÊÕµ½Êı¾İ°üÊ±£¬ÍøÂçÉè±¸Çı¶¯»á°Ñ×Ô¼ºµÄnapi_struct¹Òµ½CPUË½ÓĞ±äÁ¿ÉÏ¡£
ÕâÑùÔÚÈíÖĞ¶ÏÊ±£¬net_rx_action»á±éÀúcpuË½ÓĞ±äÁ¿µÄpoll_list£¬Ö´ĞĞÉÏÃæËù¹ÒµÄnapi_struct½á¹¹µÄpoll¹³×Óº¯Êı,½«Êı¾İ°ü´ÓÇı¶¯´«µ½ÍøÂçĞ­ÒéÕ»¡£

NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£
·ÇNAPIµÄnapi_struct½á¹¹ÊÇÄ¬ÈÏµÄ£¬Ò²¾ÍÊÇper cpuµÄsoftnet_data>backlog£¬Æğpoll¹³×Óº¯ÊıÎªprocess_backlog
*/
static inline void ____napi_schedule(struct softnet_data *sd,
				     struct napi_struct *napi)
{
	list_add_tail(&napi->poll_list, &sd->poll_list);
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
}

#ifdef CONFIG_RPS

/* One global table that all flow-based protocols share. */
struct rps_sock_flow_table *rps_sock_flow_table __read_mostly;
EXPORT_SYMBOL(rps_sock_flow_table);

/*
 * get_rps_cpu is called from netif_receive_skb and returns the target
 * CPU from the RPS map of the receiving queue for a given skb.
 * rcu_read_lock must be held on entry.
 */
static int get_rps_cpu(struct net_device *dev, struct sk_buff *skb,
		       struct rps_dev_flow **rflowp)
{
	struct ipv6hdr *ip6;
	struct iphdr *ip;
	struct netdev_rx_queue *rxqueue;
	struct rps_map *map;
	struct rps_dev_flow_table *flow_table;
	struct rps_sock_flow_table *sock_flow_table;
	int cpu = -1;
	u8 ip_proto;
	u16 tcpu;
	u32 addr1, addr2, ihl;
	union {
		u32 v32;
		u16 v16[2];
	} ports;

	if (skb_rx_queue_recorded(skb)) {
		u16 index = skb_get_rx_queue(skb);
		if (unlikely(index >= dev->num_rx_queues)) {
			WARN_ONCE(dev->num_rx_queues > 1, "%s received packet "
				"on queue %u, but number of RX queues is %u\n",
				dev->name, index, dev->num_rx_queues);
			goto done;
		}
		rxqueue = dev->_rx + index;
	} else
		rxqueue = dev->_rx;

	if (!rxqueue->rps_map && !rxqueue->rps_flow_table)
		goto done;

	if (skb->rxhash)
		goto got_hash; /* Skip hash computation on packet header */

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		if (!pskb_may_pull(skb, sizeof(*ip)))
			goto done;

		ip = (struct iphdr *) skb->data;
		ip_proto = ip->protocol;
		addr1 = (__force u32) ip->saddr;
		addr2 = (__force u32) ip->daddr;
		ihl = ip->ihl;
		break;
	case __constant_htons(ETH_P_IPV6):
		if (!pskb_may_pull(skb, sizeof(*ip6)))
			goto done;

		ip6 = (struct ipv6hdr *) skb->data;
		ip_proto = ip6->nexthdr;
		addr1 = (__force u32) ip6->saddr.s6_addr32[3];
		addr2 = (__force u32) ip6->daddr.s6_addr32[3];
		ihl = (40 >> 2);
		break;
	default:
		goto done;
	}
	switch (ip_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		if (pskb_may_pull(skb, (ihl * 4) + 4)) {
			ports.v32 = * (__force u32 *) (skb->data + (ihl * 4));
			if (ports.v16[1] < ports.v16[0])
				swap(ports.v16[0], ports.v16[1]);
			break;
		}
	default:
		ports.v32 = 0;
		break;
	}

	/* get a consistent hash (same value on both flow directions) */
	if (addr2 < addr1)
		swap(addr1, addr2);
	skb->rxhash = jhash_3words(addr1, addr2, ports.v32, hashrnd);
	if (!skb->rxhash)
		skb->rxhash = 1;

got_hash:
	flow_table = rcu_dereference(rxqueue->rps_flow_table);
	sock_flow_table = rcu_dereference(rps_sock_flow_table);
	if (flow_table && sock_flow_table) {
		u16 next_cpu;
		struct rps_dev_flow *rflow;

		rflow = &flow_table->flows[skb->rxhash & flow_table->mask];
		tcpu = rflow->cpu;

		next_cpu = sock_flow_table->ents[skb->rxhash &
		    sock_flow_table->mask];

		/*
		 * If the desired CPU (where last recvmsg was done) is
		 * different from current CPU (one in the rx-queue flow
		 * table entry), switch if one of the following holds:
		 *   - Current CPU is unset (equal to RPS_NO_CPU).
		 *   - Current CPU is offline.
		 *   - The current CPU's queue tail has advanced beyond the
		 *     last packet that was enqueued using this table entry.
		 *     This guarantees that all previous packets for the flow
		 *     have been dequeued, thus preserving in order delivery.
		 */
		if (unlikely(tcpu != next_cpu) &&
		    (tcpu == RPS_NO_CPU || !cpu_online(tcpu) ||
		     ((int)(per_cpu(softnet_data, tcpu).input_queue_head -
		      rflow->last_qtail)) >= 0)) {
			tcpu = rflow->cpu = next_cpu;
			if (tcpu != RPS_NO_CPU)
				rflow->last_qtail = per_cpu(softnet_data,
				    tcpu).input_queue_head;
		}
		if (tcpu != RPS_NO_CPU && cpu_online(tcpu)) {
			*rflowp = rflow;
			cpu = tcpu;
			goto done;
		}
	}

	map = rcu_dereference(rxqueue->rps_map);
	if (map) {
		tcpu = map->cpus[((u64) skb->rxhash * map->len) >> 32];

		if (cpu_online(tcpu)) {
			cpu = tcpu;
			goto done;
		}
	}

done:
	return cpu;
}

/* Called from hardirq (IPI) context */
static void rps_trigger_softirq(void *data)
{
	struct softnet_data *sd = data;

	____napi_schedule(sd, &sd->backlog);
	sd->received_rps++;
}

#endif /* CONFIG_RPS */

/*
 * Check if this softnet_data structure is another cpu one
 * If yes, queue it to our IPI list and return 1
 * If no, return 0
 */
static int rps_ipi_queued(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	struct softnet_data *mysd = &__get_cpu_var(softnet_data);

	if (sd != mysd) {
		sd->rps_ipi_next = mysd->rps_ipi_list;
		mysd->rps_ipi_list = sd;

		__raise_softirq_irqoff(NET_RX_SOFTIRQ);
		return 1;
	}
#endif /* CONFIG_RPS */
	return 0;
}

/*
 * enqueue_to_backlog is called to queue an skb to a per CPU backlog
 * queue (may be a remote CPU queue).
 */

/* ¶ÓÁĞÖĞ.ÔÚÖĞ¶ÏÂÖÑ¯µÄÊ±ºò,ÈíÖĞ¶Ï×Üº¯Êıdo_softirq()Ö±½Óµ½´ïÍø¿¨µÄ½ÓÊÕÈíÖĞ¶Ïº¯Êınet_rx_action()£¬
   ÔÚ´Ëº¯ÊıÖĞµ÷ÓÃqueue->backlog_dev.poll=process_backlog;¼´process_backlog()º¯Êı£¬Ëü½«queue->input_pkt_queue
   ¶ÓÁĞÖĞµÄÊı¾İÏòÉÏ²ãĞ­Òé´«Êä£¬±ÈÈçÍøÂç²ãµÄipĞ­ÒéµÈ¡£
*/
/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            porcess_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/
//Í¨¹ıÓ²¼şÖĞ¶Ï½ÓÊÕSKB£¬È»ºóÔÚÓ²¼şÖĞ¶ÏÖĞ¼ÌĞøÖ´ĞĞÏÂÃæµÄº¯Êı¡£
static int enqueue_to_backlog(struct sk_buff *skb, int cpu,
			      unsigned int *qtail)
{
	struct softnet_data *sd;
	unsigned long flags;

	sd = &per_cpu(softnet_data, cpu);

	local_irq_save(flags);//¹ØÖĞ¶Ï£¬µ±¸ÃSKBÌí¼Óµ½ÊäÈë¶ÓÁĞinput_pkt_queueºó´ò¿ªÖĞ¶Ï£¬¼ÌĞø´ÓÓ²¼şÖĞ¶ÏÖĞ½ÓÊÕÊäÈëÈ»ºó·ÅÈë¸Ã½ÓÊÕ¶ÓÁĞÖĞ

	rps_lock(sd);
	if (skb_queue_len(&sd->input_pkt_queue) <= netdev_max_backlog) {  /* ¿Õ¼äÒÑÓĞ´æ´¢µÄÊı¾İÖ¡ */
        
		if (skb_queue_len(&sd->input_pkt_queue)) {
enqueue:
        /* ¶ÓÁĞÖĞ.ÔÚÖĞ¶ÏÂÖÑ¯µÄÊ±ºò,ÈíÖĞ¶Ï×Üº¯Êıdo_softirq()Ö±½Óµ½´ïÍø¿¨µÄ½ÓÊÕÈíÖĞ¶Ïº¯Êınet_rx_action()£¬
           ÔÚ´Ëº¯ÊıÖĞµ÷ÓÃqueue->backlog_dev.poll=process_backlog;¼´process_backlog()º¯Êı£¬Ëü½«queue->input_pkt_queue
           ¶ÓÁĞÖĞµÄÊı¾İÏòÉÏ²ãĞ­Òé´«Êä£¬±ÈÈçÍøÂç²ãµÄipĞ­ÒéµÈ¡£
        	*/
			__skb_queue_tail(&sd->input_pkt_queue, skb);  /* ¹Òsoftnet_dataÊäÈë¶ÓÁĞ */ //net_rx_actionÖĞ»á¶Ô°üµÄ¸öÊı£¬ÒÔ¼°ÈíÖĞ¶Ï´¦ÀíÊ±¼ä½øĞĞÏŞÖÆ
            
			input_queue_tail_incr_save(sd, qtail);
			rps_unlock(sd);
			local_irq_restore(flags);//´ò¿ªÖĞ¶Ï£¬µ±¸ÃSKBÌí¼Óµ½ÊäÈë¶ÓÁĞinput_pkt_queueºó´ò¿ªÖĞ¶Ï£¬¼ÌĞø´ÓÓ²¼şÖĞ¶ÏÖĞ½ÓÊÕÊäÈëÈ»ºó·ÅÈë¸Ã½ÓÊÕ¶ÓÁĞÖĞ
			return NET_RX_SUCCESS;
		}

		/* Schedule NAPI for backlog device
		 * We can use non atomic operation since we own the queue lock
		 */
		if (!__test_and_set_bit(NAPI_STATE_SCHED, &sd->backlog.state)) {
			if (!rps_ipi_queued(sd))

			    /* &sd->backlog¼ÓÈënapi->poll_list£¬backlog¼´º¯Êıprocess_backlog */
				____napi_schedule(sd, &sd->backlog); //ÕâÀï¾Í»áµ÷ÓÃnet_dev_initÖĞµÄ->backlog_dev.poll=process_backlog´Ó¶øµ½process_backlogÖĞÖ´ĞĞ
		}
		goto enqueue;
	}

	sd->dropped++;
	rps_unlock(sd);

	local_irq_restore(flags);

	kfree_skb(skb);
	return NET_RX_DROP;
}

/**
 *	netif_rx	-	post buffer to the network code
 *	@skb: buffer to post
 *
 *	This function receives a packet from a device driver and queues it for
 *	the upper (protocol) levels to process.  It always succeeds. The buffer
 *	may be dropped during processing for congestion control or by the
 *	protocol layers.
 *
 *	return values:
 *	NET_RX_SUCCESS	(no congestion)
 *	NET_RX_DROP     (packet was dropped)
 *
 */
//µ±µ×²ãÉè±¸Çı¶¯³ÌĞò½ÓÊÕÒ»¸ö±¨ÎÄÊ±£¬¾Í»áÍ¨¹ıµ÷ÓÃnetif_rx½«±¨ÎÄµÄSKBÉÏ´«ÖÁÍøÂç²ã¡£
/*
ÔÚnetif_rxº¯ÊıÖĞ»áµ÷ÓÃnetif_rx_schedule, È»ºó¸Ãº¯ÊıÓÖ»áÈ¥µ÷ÓÃ__netif_rx_schedule
ÔÚº¯Êı__netif_rx_scheduleÖĞ»áÈ¥´¥·¢ÈíÖĞ¶ÏNET_RX_SOFTIRQ, Ò²¼´ÊÇÈ¥µ÷ÓÃnet_rx_action.
È»ºóÔÚnet_rx_actionº¯ÊıÖĞ»áÈ¥µ÷ÓÃÉè±¸µÄpollº¯Êı, ËüÊÇÉè±¸×Ô¼º×¢²áµÄ.
ÔÚÉè±¸µÄpollº¯ÊıÖĞ, »áÈ¥µ÷ÓÃnetif_receive_skbº¯Êı,  ÔÚ¸Ãº¯ÊıÖĞÓĞÏÂÃæÒ»ÌõÓï¾ä pt_prev->func, ´Ë´¦µÄfuncÎªÒ»¸öº¯ÊıÖ¸Õë, ÔÚÖ®Ç°µÄ×¢²áÖĞÉèÖÃÎªip_rcv.
Òò´Ë, ¾ÍÍê³ÉÁË´ÓÁ´Â·²ãÉÏ´«µ½ÍøÂç²ãµÄÕâÒ»¸ö¹ı³ÌÁË.
*/ //·ÇNAPI·½Ê½£¬´ÓÇı¶¯Ó²¼şÖĞ¶ÏÖĞµ÷ÓÃÕâ¸önetif_rxº¯Êı£¬¶øNAPI·½Ê½´ÓÓ²¼şÖĞ¶ÏÖĞµ÷ÓÃnapi_schedule¼¤»îÈíÖĞ¶Ï, ²Î¿¼ Êı¾İ°ü½ÓÊÕÏµÁĞ ¡ª NAPIµÄÔ­ÀíºÍÊµÏÖ http://blog.csdn.net/zhangskd/article/details/21627963

/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            process_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/
int netif_rx(struct sk_buff *skb)
{
	int ret;

	/* if netpoll wants it, pretend we never saw it */
	if (netpoll_rx(skb))
		return NET_RX_DROP;

	if (netdev_tstamp_prequeue)
		net_timestamp_check(skb);

#ifdef CONFIG_RPS
	{
		struct rps_dev_flow voidflow, *rflow = &voidflow;
		int cpu;

		preempt_disable();
		rcu_read_lock();

		cpu = get_rps_cpu(skb->dev, skb, &rflow);
		if (cpu < 0)
			cpu = smp_processor_id();

		ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);//ÕâÀïÃæµÄÊı¾İÔÙprocess_backlog

		rcu_read_unlock();
		preempt_enable();
	}
#else
	{
		unsigned int qtail;
		ret = enqueue_to_backlog(skb, get_cpu(), &qtail);
		put_cpu();
	}
#endif
	return ret;
}
EXPORT_SYMBOL(netif_rx);

int netif_rx_ni(struct sk_buff *skb)
{
	int err;

	preempt_disable();
	err = netif_rx(skb);
	if (local_softirq_pending())
		do_softirq();
	preempt_enable();

	return err;
}
EXPORT_SYMBOL(netif_rx_ni);

/*
  * net_tx_action()ÊÇÊı¾İ°üÊä³öÈíÖĞ¶ÏµÄÀı³Ì£¬
  * Ò»µ©¼¤»î±ã»á±éÀúoutput_queue¶ÓÁĞÖĞ
  * ´ı´¦ÀíµÄÊä³öÍøÂçÉè±¸£¬È»ºóµ÷ÓÃ
  * qdisc_run()ÔÚºÏÊÊµÄÊ±»ú·¢ËÍÊı¾İ°ü¡£
  * Êı¾İ°üÊä³öÈíÖĞ¶ÏÍ¨³£ÓĞnetif_schedule()¼¤»î¡£
  */ //qos tc Á÷Á¿¿ØÖÆµÄÊ±ºò»áÓÃµ½
static void net_tx_action(struct softirq_action *h)
{
	struct softnet_data *sd = &__get_cpu_var(softnet_data);

	/*
	  * Èç¹ûµ±Ç°CPUµÄsoftnet_dataÖĞ´æÔÚÒÑÍê³É
	  * Êä³ö´ıÊÍ·ÅµÄÊı¾İ°ü£¬Ôò±éÀú
	  * completion_queue¶ÓÁĞ£¬ÊÍ·Å¸Ã¶ÓÁĞÖĞËùÓĞ
	  * Êı¾İ°ü
	  */
	if (sd->completion_queue) {
		struct sk_buff *clist;

		local_irq_disable();
		clist = sd->completion_queue;
		sd->completion_queue = NULL;
		local_irq_enable();

		while (clist) {
			struct sk_buff *skb = clist;
			clist = clist->next;

			WARN_ON(atomic_read(&skb->users));
			__kfree_skb(skb);
		}
	}

	/*
	  * Èç¹ûµ±Ç°CPUµÄsoftnet_dataÖĞ´æÔÚ´ı´¦ÀíµÄÊä³öÍøÂç
	  * Éè±¸£¬Ôò±éÀúoutput_queue¶ÓÁĞ£¬µ÷ÓÃqdisc_run()À´·¢ËÍ
	  * Êı¾İ°ü»òÕßÔÙ´Îµ÷¶ÈÊı¾İ°üÊä³öÈíÖĞ¶Ï£¬ÔÚ
	  * ºÏÊÊµÄÊ±»ú·¢ËÍÊı¾İ°ü¡£
	  */
	if (sd->output_queue) {
		struct Qdisc *head;

		local_irq_disable();
		head = sd->output_queue;
		sd->output_queue = NULL;
		local_irq_enable();

		while (head) {
			struct Qdisc *q = head;
			spinlock_t *root_lock;

			head = head->next_sched;

			root_lock = qdisc_lock(q);
			if (spin_trylock(root_lock)) {
				smp_mb__before_clear_bit();
				clear_bit(__QDISC_STATE_SCHED,
					  &q->state);
				qdisc_run(q);
				spin_unlock(root_lock);
			} else {
				if (!test_bit(__QDISC_STATE_DEACTIVATED,
					      &q->state)) {
					__netif_reschedule(q);
				} else {
					smp_mb__before_clear_bit();
					clear_bit(__QDISC_STATE_SCHED,
						  &q->state);
				}
			}
		}
	}
}

static inline int deliver_skb(struct sk_buff *skb,
			      struct packet_type *pt_prev,
			      struct net_device *orig_dev)
{
	atomic_inc(&skb->users);
	return pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
}

#if defined(CONFIG_BRIDGE) || defined (CONFIG_BRIDGE_MODULE)

#if defined(CONFIG_ATM_LANE) || defined(CONFIG_ATM_LANE_MODULE)
/* This hook is defined here for ATM LANE */
int (*br_fdb_test_addr_hook)(struct net_device *dev,
			     unsigned char *addr) __read_mostly;
EXPORT_SYMBOL_GPL(br_fdb_test_addr_hook);
#endif

/*
 * If bridge module is loaded call bridging hook.
 *  returns NULL if packet was consumed.
 */ //ÕâÊÇÒ»¸öº¯ÊıÖ¸Õë
struct sk_buff *(*br_handle_frame_hook)(struct net_bridge_port *p, struct sk_buff *skb) ;//__read_mostly;
EXPORT_SYMBOL_GPL(br_handle_frame_hook);

static inline struct sk_buff *handle_bridge(struct sk_buff *skb,
					    struct packet_type **pt_prev, int *ret,
					    struct net_device *orig_dev)
{
	struct net_bridge_port *port;

	if (skb->pkt_type == PACKET_LOOPBACK ||
	    (port = rcu_dereference(skb->dev->br_port)) == NULL)
		return skb;

	if (*pt_prev) {
		*ret = deliver_skb(skb, *pt_prev, orig_dev);
		*pt_prev = NULL;
	}

	return br_handle_frame_hook(port, skb); //br_handle_frame_hook = br_handle_frame;
}
#else
#define handle_bridge(skb, pt_prev, ret, orig_dev)	(skb)
#endif

#if defined(CONFIG_MACVLAN) || defined(CONFIG_MACVLAN_MODULE)
struct sk_buff *(*macvlan_handle_frame_hook)(struct macvlan_port *p,
					     struct sk_buff *skb) __read_mostly;
EXPORT_SYMBOL_GPL(macvlan_handle_frame_hook);

static inline struct sk_buff *handle_macvlan(struct sk_buff *skb,
					     struct packet_type **pt_prev,
					     int *ret,
					     struct net_device *orig_dev)
{
	struct macvlan_port *port;

	port = rcu_dereference(skb->dev->macvlan_port);
	if (!port)
		return skb;

	if (*pt_prev) {
		*ret = deliver_skb(skb, *pt_prev, orig_dev);
		*pt_prev = NULL;
	}
	return macvlan_handle_frame_hook(port, skb);
}
#else
#define handle_macvlan(skb, pt_prev, ret, orig_dev)	(skb)
#endif

#ifdef CONFIG_NET_CLS_ACT
/* TODO: Maybe we should just force sch_ingress to be compiled in
 * when CONFIG_NET_CLS_ACT is? otherwise some useless instructions
 * a compare and 2 stores extra right now if we dont have it on
 * but have CONFIG_NET_CLS_ACT
 * NOTE: This doesnt stop any functionality; if you dont have
 * the ingress scheduler, you just cant add policies on ingress.
 *
 */
static int ing_filter(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	u32 ttl = G_TC_RTTL(skb->tc_verd);
	struct netdev_queue *rxq;
	int result = TC_ACT_OK;
	struct Qdisc *q;

	if (MAX_RED_LOOP < ttl++) {
		printk(KERN_WARNING
		       "Redir loop detected Dropping packet (%d->%d)\n",
		       skb->skb_iif, dev->ifindex);
		return TC_ACT_SHOT;
	}

	skb->tc_verd = SET_TC_RTTL(skb->tc_verd, ttl);
	skb->tc_verd = SET_TC_AT(skb->tc_verd, AT_INGRESS);

	rxq = &dev->rx_queue;

	q = rxq->qdisc;
	if (q != &noop_qdisc) {
		spin_lock(qdisc_lock(q));
		if (likely(!test_bit(__QDISC_STATE_DEACTIVATED, &q->state)))
			result = qdisc_enqueue_root(skb, q); //ingress_qdisc_ops
		spin_unlock(qdisc_lock(q));
	}

	return result;
}

/*
½øÈë³ö¿ÚÁ÷¿ØµÄº¯ÊıÎªdev_queue_xmit(); Èç¹ûÊÇÈë¿ÚÁ÷¿Ø, Êı¾İÖ»ÊÇ¸Õ´ÓÍø¿¨Éè±¸ÖĞÊÕµ½, »¹Î´½»µ½ÍøÂçÉÏ²ã´¦Àí, ²»¹ıÍø¿¨µÄÈë¿ÚÁ÷¿Ø²»ÊÇ±ØĞëµÄ, 
È±Ê¡Çé¿öÏÂ²¢²»½øĞĞÁ÷¿Ø£¬½øÈëÈë¿ÚÁ÷¿Øº¯ÊıÎªing_filter()º¯Êı£¬¸Ãº¯Êı±»skb_receive_skb()µ÷ÓÃ¡£
*///ĞèÒª±àÒëÄÚºËµÄÊ±ºò£¬±àÒëCONFIG_NET_CLS_ACT
static inline struct sk_buff *handle_ing(struct sk_buff *skb,
					 struct packet_type **pt_prev,
					 int *ret, struct net_device *orig_dev)
{
	if (skb->dev->rx_queue.qdisc == &noop_qdisc)
		goto out;

	if (*pt_prev) {
		*ret = deliver_skb(skb, *pt_prev, orig_dev);
		*pt_prev = NULL;
	} else {
		/* Huh? Why does turning on AF_PACKET affect this? */
		skb->tc_verd = SET_TC_OK2MUNGE(skb->tc_verd);
	}

	switch (ing_filter(skb)) {
	case TC_ACT_SHOT:
	case TC_ACT_STOLEN:
		kfree_skb(skb);
		return NULL;
	}

out:
	skb->tc_verd = 0;
	return skb;
}
#endif

/*
 * 	netif_nit_deliver - deliver received packets to network taps
 * 	@skb: buffer
 *
 * 	This function is used to deliver incoming packets to network
 * 	taps. It should be used when the normal netif_receive_skb path
 * 	is bypassed, for example because of VLAN acceleration.
 */
void netif_nit_deliver(struct sk_buff *skb)
{
	struct packet_type *ptype;

	if (list_empty(&ptype_all))
		return;

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->mac_len = skb->network_header - skb->mac_header;

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, &ptype_all, list) {
		if (!ptype->dev || ptype->dev == skb->dev)
			deliver_skb(skb, ptype, skb->dev);
	}
	rcu_read_unlock();
}

static inline void skb_bond_set_mac_by_master(struct sk_buff *skb,
					      struct net_device *master)
{
	if (skb->pkt_type == PACKET_HOST) {
		u16 *dest = (u16 *) eth_hdr(skb)->h_dest;

		memcpy(dest, master->dev_addr, ETH_ALEN);
	}
}

/* On bonding slaves other than the currently active slave, suppress
 * duplicates except for 802.3ad ETH_P_SLOW, alb non-mcast/bcast, and
 * ARP on active-backup slaves with arp_validate enabled.
 */
int __skb_bond_should_drop(struct sk_buff *skb, struct net_device *master)
{
	struct net_device *dev = skb->dev;

	if (master->priv_flags & IFF_MASTER_ARPMON)
		dev->last_rx = jiffies;

	if ((master->priv_flags & IFF_MASTER_ALB) && master->br_port) {
		/* Do address unmangle. The local destination address
		 * will be always the one master has. Provides the right
		 * functionality in a bridge.
		 */
		skb_bond_set_mac_by_master(skb, master);
	}

	if (dev->priv_flags & IFF_SLAVE_INACTIVE) {
		if ((dev->priv_flags & IFF_SLAVE_NEEDARP) &&
		    skb->protocol == __cpu_to_be16(ETH_P_ARP))
			return 0;

		if (master->priv_flags & IFF_MASTER_ALB) {
			if (skb->pkt_type != PACKET_BROADCAST &&
			    skb->pkt_type != PACKET_MULTICAST)
				return 0;
		}
		if (master->priv_flags & IFF_MASTER_8023AD &&
		    skb->protocol == __cpu_to_be16(ETH_P_SLOW))
			return 0;

		return 1;
	}
	return 0;
}
EXPORT_SYMBOL(__skb_bond_should_drop);

/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            process_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/
static int __netif_receive_skb(struct sk_buff *skb)
{
	struct packet_type *ptype, *pt_prev;
	struct net_device *orig_dev;
	struct net_device *master;
	struct net_device *null_or_orig;
	struct net_device *orig_or_bond;
	int ret = NET_RX_DROP;
	__be16 type;

	if (!netdev_tstamp_prequeue)
		net_timestamp_check(skb);

	if (vlan_tx_tag_present(skb) && vlan_hwaccel_do_receive(skb))
		return NET_RX_SUCCESS;

	/* if we've gotten here through NAPI, check netpoll */
	if (netpoll_receive_skb(skb))
		return NET_RX_DROP;

	if (!skb->skb_iif)
		skb->skb_iif = skb->dev->ifindex;

	/*
	 * bonding note: skbs received on inactive slaves should only
	 * be delivered to pkt handlers that are exact matches.  Also
	 * the deliver_no_wcard flag will be set.  If packet handlers
	 * are sensitive to duplicate packets these skbs will need to
	 * be dropped at the handler.  The vlan accel path may have
	 * already set the deliver_no_wcard flag.
	 */
	null_or_orig = NULL;
	orig_dev = skb->dev;
	master = ACCESS_ONCE(orig_dev->master);
	if (skb->deliver_no_wcard)
		null_or_orig = orig_dev;
	else if (master) {
		if (skb_bond_should_drop(skb, master)) {
			skb->deliver_no_wcard = 1;
			null_or_orig = orig_dev; /* deliver only exact match */
		} else
			skb->dev = master;
	}

	__get_cpu_var(softnet_data).processed++;

	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb->mac_len = skb->network_header - skb->mac_header;

	pt_prev = NULL;

	rcu_read_lock();

#ifdef CONFIG_NET_CLS_ACT
	if (skb->tc_verd & TC_NCLS) {
		skb->tc_verd = CLR_TC_NCLS(skb->tc_verd);
		goto ncls;
	}
#endif
    /*    
    po->prot_hook.func = packet_rcv;
    if (sock->type == SOCK_PACKET)
        po->prot_hook.func = packet_rcv_spkt;
    */
	list_for_each_entry_rcu(ptype, &ptype_all, list) {  //ÔÚnet_dev_initÖĞ³õÊ¼»¯
	    /*×¢ÒâÕâÀï²¢Ã»ÓĞÒªÇóptype->type == type£¬ËùÒÔ½ÓÊÕµ½µÄ°üÖ»ÒªÓĞ×¢²áETH_P_ALLĞ­Òé£¬ËùÓĞµÄ°ü¶¼»á×ßµ½deliver_skb*/
		if (ptype->dev == null_or_orig || ptype->dev == skb->dev ||
		    ptype->dev == orig_dev) { //ÉÏÃæµÄpaket_type.type Îª ETH_P_ALL    
		    if (pt_prev)
		        /* ÕâÊÇÖ´ĞĞÉÏÒ»´Î±éÀúÖĞµÄ£¬ËùÒÔÈç¹ûÖ»×¢²áÒ»¸öETH_P_ALLµÄ»°Ôòpt_prev->func»áÔÚÕâ¸öÑ­»·ÍâµÄdeliver_skbÖĞÖ´ĞĞ */
				ret = deliver_skb(skb, pt_prev, orig_dev);//´Ëº¯Êı×îÖÕµ÷ÓÃpaket_type.func()   packet_rcv_spkt»òÕßpacket_rcv
			pt_prev = ptype;
		}
	}

#ifdef CONFIG_NET_CLS_ACT
	skb = handle_ing(skb, &pt_prev, &ret, orig_dev);
	if (!skb)
		goto out;
ncls:
#endif

    /* 
    Èô±àÒëÄÚºËÊ±Ñ¡ÉÏBRIDGE£¬ÏÂÃæ»áÖ´ĞĞÍøÇÅÄ£¿é
    //µ÷ÓÃº¯ÊıÖ¸Õë br_handle_frame_hook(skb), ÔÚ¶¯Ì¬Ä£¿é linux_2_6_24/net/bridge/br.cÖĞ
       //br_handle_frame_hook = br_handle_frame;
       //ËùÒÔÊµ¼Êº¯Êı br_handle_frame¡£
       //×¢Òâ£ºÔÚ´ËÍøÇÅÄ£¿éÀï³õÊ¼»¯ skb->pkt_type Îª PACKET_HOST¡¢PACKET_OTHERHOST
       ¼ûº¯Êıbr_init
    */
	skb = handle_bridge(skb, &pt_prev, &ret, orig_dev);
	if (!skb)
		goto out;

	/*
        ±àÒëÄÚºËÊ±Ñ¡ÉÏMAC_VLANÄ£¿é£¬ÏÂÃæ²Å»áÖ´ĞĞ
        //µ÷ÓÃ macvlan_handle_frame_hook(skb), ÔÚ¶¯Ì¬Ä£¿élinux_2_6_24/drivers/net/macvlan.cÖĞ
        //macvlan_handle_frame_hook = macvlan_handle_frame; 
        //ËùÒÔÊµ¼Êº¯ÊıÎª macvlan_handle_frame¡£ 
        //×¢Òâ£º´Ëº¯ÊıÀï»á³õÊ¼»¯ skb->pkt_type Îª PACKET_BROADCAST¡¢PACKET_MULTICAST¡¢PACKET_HOST
	*/
	skb = handle_macvlan(skb, &pt_prev, &ret, orig_dev);
	if (!skb)
		goto out;

	/*
	 * Make sure frames received on VLAN interfaces stacked on
	 * bonding interfaces still make their way to any base bonding
	 * device that may have registered for a specific ptype.  The
	 * handler may have to adjust skb->dev and orig_dev.
	 */
	orig_or_bond = orig_dev;
	if ((skb->dev->priv_flags & IFF_802_1Q_VLAN) &&
	    (vlan_dev_real_dev(skb->dev)->priv_flags & IFF_BONDING)) {
		orig_or_bond = vlan_dev_real_dev(skb->dev);
	}
    
    /*
    ×îºó type = skb->protocol; &ptype_base[ntohs(type)&15]
        //´¦Àíptype_base[ntohs(type)&15]ÉÏµÄËùÓĞµÄ packet_type->func()
        //¸ù¾İµÚ¶ş²ã²»Í¬Ğ­ÒéÀ´½øÈë²»Í¬µÄ¹³×Óº¯Êı£¬ÖØÒªµÄÓĞ£ºip_rcv() arp_rcv()
        ip_recv¼ûinet_initÀïÃæµÄdev_add_pack(&ip_packet_type);
    */
	type = skb->protocol; //skb->protocolÓÃÀ´±íÊ¾´ËSKB°üº¬µÄÊı¾İËùÖ§³ÖµÄL3²ãĞ­ÒéÊÇÊ²Ã´. Èçox0800´ú±íIP£¬0x0806´ú±íARP ÔÚÇı¶¯³ÌĞòÖĞÒÑ¾­»ñÈ¡ÁË¸ÃÖµ
    
	list_for_each_entry_rcu(ptype,
			&ptype_base[ntohs(type) & PTYPE_HASH_MASK], list) {
		if (ptype->type == type && (ptype->dev == null_or_orig ||
		     ptype->dev == skb->dev || ptype->dev == orig_dev ||
		     ptype->dev == orig_or_bond)) {
			if (pt_prev)
			    /*/* ÕâÊÇÖ´ĞĞÉÏÒ»´Î±éÀúÖĞµÄ£¬ËùÒÔÈç¹ûÖ»×¢²áÒ»¸öETH_P_ALLµÄ»°Ôòpt_prev->func»áÔÚÕâ¸öÑ­»·ÍâµÄdeliver_skbÖĞÖ´ĞĞ */*/
				ret = deliver_skb(skb, pt_prev, orig_dev);
			pt_prev = ptype;
		}
	}

	if (pt_prev) {
		ret = pt_prev->func(skb, skb->dev, pt_prev, orig_dev);
	} else {
		kfree_skb(skb);
		/* Jamal, now you will not able to escape explaining
		 * me how you were going to use this. :-)
		 */
		ret = NET_RX_DROP;
	}

out:
	rcu_read_unlock();
	return ret;
}

/**
 *	netif_receive_skb - process receive buffer from network
 *	@skb: buffer to process
 *
 *	netif_receive_skb() is the main receive data processing function.
 *	It always succeeds. The buffer may be dropped during processing
 *	for congestion control or by the protocol layers.
 *
 *	This function may only be called from softirq context and interrupts
 *	should be enabled.
 *
 *	Return values (usually ignored):
 *	NET_RX_SUCCESS: no congestion
 *	NET_RX_DROP: packet was dropped  ½øÈë¶ş²ãĞ­Òé´¦Àíº¯Êı
 */ //    netif_receive_skbÊÇÁ´Â·²ã½ÓÊÕÊı¾İ±¨µÄ×îºóÒ»Õ¾¡£Ëü¸ù¾İ×¢²áÔÚÈ«¾ÖÊı×éptype_allºÍptype_baseÀïµÄÍøÂç²ãÊı¾İ±¨ÀàĞÍ£¬°ÑÊı¾İ±¨µİ½»¸ø²»Í¬µÄÍøÂç²ãĞ­ÒéµÄ½ÓÊÕº¯Êı(INETÓòÖĞÖ÷ÒªÊÇip_rcvºÍarp_rcv)¡£
/*
ÔÚnetif_receive_skb()º¯ÊıÖĞ£¬¿ÉÒÔ¿´³ö´¦ÀíµÄÊÇÏñARP¡¢IPÕâĞ©Á´Â·²ãÒÔÉÏµÄĞ­Òé£¬ÄÇÃ´£¬Á´Â·²ã±¨Í·ÊÇÔÚÄÄÀïÈ¥µôµÄÄØ£¿´ğ°¸ÊÇÍø¿¨Çı¶¯ÖĞ£¬
ÔÚµ÷ÓÃnetif_receive_skb()Ç°£¬
±¾ÆªÎÄÕÂÀ´Ô´ÓÚ Linux¹«ÉçÍøÕ¾(www.linuxidc.com)  Ô­ÎÄÁ´½Ó£ºhttp://www.linuxidc.com/Linux/2011-05/36065.htm
*/
/*
½ÓÊÕÊı¾İ°üµÄÏÂ°ë²¿´¦ÀíÁ÷³ÌÎª£º
net_rx_action // ÈíÖĞ¶Ï
    |--> process_backlog() // Ä¬ÈÏpoll
               |--> __netif_receive_skb() // L2´¦Àíº¯Êı
                            |--> ip_rcv() // L3Èë¿Ú

*/

/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            porcess_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/

int netif_receive_skb(struct sk_buff *skb)
{
	if (netdev_tstamp_prequeue)
		net_timestamp_check(skb);

#ifdef CONFIG_RPS
	{
		struct rps_dev_flow voidflow, *rflow = &voidflow;
		int cpu, ret;

		rcu_read_lock();

		cpu = get_rps_cpu(skb->dev, skb, &rflow);

		if (cpu >= 0) {
			ret = enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
			rcu_read_unlock();
		} else {
			rcu_read_unlock();
			ret = __netif_receive_skb(skb);
		}

		return ret;
	}
#else
	return __netif_receive_skb(skb);
#endif
}
EXPORT_SYMBOL(netif_receive_skb);

/* Network device is going away, flush any packets still pending
 * Called with irqs disabled.
 */
static void flush_backlog(void *arg)
{
	struct net_device *dev = arg;
	struct softnet_data *sd = &__get_cpu_var(softnet_data);
	struct sk_buff *skb, *tmp;

	rps_lock(sd);
	skb_queue_walk_safe(&sd->input_pkt_queue, skb, tmp) {
		if (skb->dev == dev) {
			__skb_unlink(skb, &sd->input_pkt_queue);
			kfree_skb(skb);
			input_queue_head_incr(sd);
		}
	}
	rps_unlock(sd);

	skb_queue_walk_safe(&sd->process_queue, skb, tmp) {
		if (skb->dev == dev) {
			__skb_unlink(skb, &sd->process_queue);
			kfree_skb(skb);
			input_queue_head_incr(sd);
		}
	}
}

static int napi_gro_complete(struct sk_buff *skb)
{
	struct packet_type *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &ptype_base[ntohs(type) & PTYPE_HASH_MASK];
	int err = -ENOENT;

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || ptype->dev || !ptype->gro_complete)
			continue;

		err = ptype->gro_complete(skb);
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);
		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return netif_receive_skb(skb);
}

static void napi_gro_flush(struct napi_struct *napi)
{
	struct sk_buff *skb, *next;

	for (skb = napi->gro_list; skb; skb = next) {
		next = skb->next;
		skb->next = NULL;
		napi_gro_complete(skb);
	}

	napi->gro_count = 0;
	napi->gro_list = NULL;
}

enum gro_result dev_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct packet_type *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &ptype_base[ntohs(type) & PTYPE_HASH_MASK];
	int same_flow;
	int mac_len;
	enum gro_result ret;

	if (!(skb->dev->features & NETIF_F_GRO) || netpoll_rx_on(skb))
		goto normal;

	if (skb_is_gso(skb) || skb_has_frags(skb))
		goto normal;

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || ptype->dev || !ptype->gro_receive)
			continue;

		skb_set_network_header(skb, skb_gro_offset(skb));
		mac_len = skb->network_header - skb->mac_header;
		skb->mac_len = mac_len;
		NAPI_GRO_CB(skb)->same_flow = 0;
		NAPI_GRO_CB(skb)->flush = 0;
		NAPI_GRO_CB(skb)->free = 0;

		pp = ptype->gro_receive(&napi->gro_list, skb);
		break;
	}
	rcu_read_unlock();

	if (&ptype->list == head)
		goto normal;

	same_flow = NAPI_GRO_CB(skb)->same_flow;
	ret = NAPI_GRO_CB(skb)->free ? GRO_MERGED_FREE : GRO_MERGED;

	if (pp) {
		struct sk_buff *nskb = *pp;

		*pp = nskb->next;
		nskb->next = NULL;
		napi_gro_complete(nskb);
		napi->gro_count--;
	}

	if (same_flow)
		goto ok;

	if (NAPI_GRO_CB(skb)->flush || napi->gro_count >= MAX_GRO_SKBS)
		goto normal;

	napi->gro_count++;
	NAPI_GRO_CB(skb)->count = 1;
	skb_shinfo(skb)->gso_size = skb_gro_len(skb);
	skb->next = napi->gro_list;
	napi->gro_list = skb;
	ret = GRO_HELD;

pull:
	if (skb_headlen(skb) < skb_gro_offset(skb)) {
		int grow = skb_gro_offset(skb) - skb_headlen(skb);

		BUG_ON(skb->end - skb->tail < grow);

		memcpy(skb_tail_pointer(skb), NAPI_GRO_CB(skb)->frag0, grow);

		skb->tail += grow;
		skb->data_len -= grow;

		skb_shinfo(skb)->frags[0].page_offset += grow;
		skb_shinfo(skb)->frags[0].size -= grow;

		if (unlikely(!skb_shinfo(skb)->frags[0].size)) {
			put_page(skb_shinfo(skb)->frags[0].page);
			memmove(skb_shinfo(skb)->frags,
				skb_shinfo(skb)->frags + 1,
				--skb_shinfo(skb)->nr_frags * sizeof(skb_frag_t));
		}
	}

ok:
	return ret;

normal:
	ret = GRO_NORMAL;
	goto pull;
}
EXPORT_SYMBOL(dev_gro_receive);

static gro_result_t
__napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	struct sk_buff *p;

	for (p = napi->gro_list; p; p = p->next) {
		NAPI_GRO_CB(p)->same_flow =
			(p->dev == skb->dev) &&
			!compare_ether_header(skb_mac_header(p),
					      skb_gro_mac_header(skb));
		NAPI_GRO_CB(p)->flush = 0;
	}

	return dev_gro_receive(napi, skb);
}

gro_result_t napi_skb_finish(gro_result_t ret, struct sk_buff *skb)
{
	switch (ret) {
	case GRO_NORMAL:
		if (netif_receive_skb(skb))
			ret = GRO_DROP;
		break;

	case GRO_DROP:
	case GRO_MERGED_FREE:
		kfree_skb(skb);
		break;

	case GRO_HELD:
	case GRO_MERGED:
		break;
	}

	return ret;
}
EXPORT_SYMBOL(napi_skb_finish);

void skb_gro_reset_offset(struct sk_buff *skb)
{
	NAPI_GRO_CB(skb)->data_offset = 0;
	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;

	if (skb->mac_header == skb->tail &&
	    !PageHighMem(skb_shinfo(skb)->frags[0].page)) {
		NAPI_GRO_CB(skb)->frag0 =
			page_address(skb_shinfo(skb)->frags[0].page) +
			skb_shinfo(skb)->frags[0].page_offset;
		NAPI_GRO_CB(skb)->frag0_len = skb_shinfo(skb)->frags[0].size;
	}
}
EXPORT_SYMBOL(skb_gro_reset_offset);
/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            porcess_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/
gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
{
	skb_gro_reset_offset(skb);

	return napi_skb_finish(__napi_gro_receive(napi, skb), skb);
}
EXPORT_SYMBOL(napi_gro_receive);

void napi_reuse_skb(struct napi_struct *napi, struct sk_buff *skb)
{
	__skb_pull(skb, skb_headlen(skb));
	skb_reserve(skb, NET_IP_ALIGN - skb_headroom(skb));
	skb->dev = napi->dev;
	skb->skb_iif = 0;

	napi->skb = skb;
}
EXPORT_SYMBOL(napi_reuse_skb);

struct sk_buff *napi_get_frags(struct napi_struct *napi)
{
	struct sk_buff *skb = napi->skb;

	if (!skb) {
		skb = netdev_alloc_skb_ip_align(napi->dev, GRO_MAX_HEAD);
		if (skb)
			napi->skb = skb;
	}
	return skb;
}
EXPORT_SYMBOL(napi_get_frags);

gro_result_t napi_frags_finish(struct napi_struct *napi, struct sk_buff *skb,
			       gro_result_t ret)
{
	switch (ret) {
	case GRO_NORMAL:
	case GRO_HELD:
		skb->protocol = eth_type_trans(skb, skb->dev);

		if (ret == GRO_HELD)
			skb_gro_pull(skb, -ETH_HLEN);
		else if (netif_receive_skb(skb))
			ret = GRO_DROP;
		break;

	case GRO_DROP:
	case GRO_MERGED_FREE:
		napi_reuse_skb(napi, skb);
		break;

	case GRO_MERGED:
		break;
	}

	return ret;
}
EXPORT_SYMBOL(napi_frags_finish);

struct sk_buff *napi_frags_skb(struct napi_struct *napi)
{
	struct sk_buff *skb = napi->skb;
	struct ethhdr *eth;
	unsigned int hlen;
	unsigned int off;

	napi->skb = NULL;

	skb_reset_mac_header(skb);
	skb_gro_reset_offset(skb);

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*eth);
	eth = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		eth = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!eth)) {
			napi_reuse_skb(napi, skb);
			skb = NULL;
			goto out;
		}
	}

	skb_gro_pull(skb, sizeof(*eth));

	/*
	 * This works because the only protocols we care about don't require
	 * special handling.  We'll fix it up properly at the end.
	 */
	skb->protocol = eth->h_proto;

out:
	return skb;
}
EXPORT_SYMBOL(napi_frags_skb);

gro_result_t napi_gro_frags(struct napi_struct *napi)
{
	struct sk_buff *skb = napi_frags_skb(napi);

	if (!skb)
		return GRO_DROP;

	return napi_frags_finish(napi, skb, __napi_gro_receive(napi, skb));
}
EXPORT_SYMBOL(napi_gro_frags);

/*
 * net_rps_action sends any pending IPI's for rps.
 * Note: called with local irq disabled, but exits with local irq enabled.
 */
static void net_rps_action_and_irq_enable(struct softnet_data *sd)
{
#ifdef CONFIG_RPS
	struct softnet_data *remsd = sd->rps_ipi_list;

	if (remsd) {
		sd->rps_ipi_list = NULL;

		local_irq_enable();

		/* Send pending IPI's to kick RPS processing on remote cpus. */
		while (remsd) {
			struct softnet_data *next = remsd->rps_ipi_next;

			if (cpu_online(remsd->cpu))
				__smp_call_function_single(remsd->cpu,
							   &remsd->csd, 0);
			remsd = next;
		}
	} else
#endif
		local_irq_enable();
}
/*
  * process_backlog()ÔÚ·ÇNAPI·½Ê½ÏÂ£¬ĞéÄâÍøÂçÉè±¸µÄ
  * ÂÖÑ¯º¯Êı¡£µ±ĞéÄâÍøÂçÉè±¸backlog_devÌí¼Óµ½
  * ÍøÂçÉè±¸ÂÖÑ¯¶ÓÁĞºó£¬ÔÚÊı¾İ°üÊäÈëÈíÖĞ¶Ï
  * ÖĞ»áµ÷ÓÃprocess_backlog()½øĞĞÊı¾İ°üµÄÊäÈë¡£
  * @napi:½øĞĞÂÖÑ¯µÄĞéÄâµÄÍøÂçÉè±¸¶ÔÓ¦µÄ½á¹¹
  * @budget:ÔÚÊı¾İ°üÊäÈëÈíÖĞ¶ÏÖĞ£¬ÍøÂçÉè±¸¶ÁÈ¡
  *               ±¨ÎÄµÄÅä¶î¡£
  */
/*
½ÓÊÕÊı¾İ°üµÄÏÂ°ë²¿´¦ÀíÁ÷³ÌÎª£º
net_rx_action // ÈíÖĞ¶Ï
    |--> process_backlog() // Ä¬ÈÏpoll
               |--> __netif_receive_skb() // L2´¦Àíº¯Êı
                            |--> ip_rcv() // L3Èë¿Ú

*/
/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            process_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/
//¸³ÖµµÄµØ·½¼ûnet_dev_init, sd->backlog.poll = process_backlog;  Ö´ĞĞ¸Ãº¯ÊıµÄµØ·½ÔÚnet_rx_action(struct softirq_action *h)
static int process_backlog(struct napi_struct *napi, int quota)
{
	int work = 0;
	struct softnet_data *sd = container_of(napi, struct softnet_data, backlog);

#ifdef CONFIG_RPS
	/* Check if we have pending ipi, its better to send them now,
	 * not waiting net_rx_action() end.
	 */
	if (sd->rps_ipi_list) {
		local_irq_disable();
		net_rps_action_and_irq_enable(sd);
	}
#endif
	napi->weight = weight_p;
	local_irq_disable();
	while (work < quota) {
		struct sk_buff *skb;
		unsigned int qlen;

		while ((skb = __skb_dequeue(&sd->process_queue))) { //ÔÚÏÂÃæµÄskb_queue_splice_tail_initÖĞ£¬±»·Åµ½ÁËprocess_queueÖĞ
			local_irq_enable();
			  /* 
               * ·ÖÎö·Ö×éÀàĞÍ£¬ÒÔ±ã¸ù¾İ·Ö×é
               * ÀàĞÍ½«·Ö×é´«µİ¸øÍøÂç²ãµÄ½ÓÊÕº¯Êı£¬
               * ¼´´«µİµ½ÍøÂçÏµÍ³µÄ¸ü¸ßÒ»²ã.Îª´Ë£¬
               * ¸Ãº¯Êı±éÀúÓĞ¿ÉÄÜ¸ºÔğµ±Ç°·Ö×éÀàĞÍµÄËùÓĞ
               * ÍøÂç²ãº¯Êı£¬Ò»Ò»µ÷ÓÃdeliver_skb
               * 
               * update:
               *   ½«µ±Ç°±¨ÎÄ´«µİµ½ÉÏ²ãĞ­ÒéÕ»
               */
			__netif_receive_skb(skb);
			local_irq_disable();
			input_queue_head_incr(sd);
			if (++work >= quota) {
				local_irq_enable();
				return work;
			}
		}

		rps_lock(sd);
		qlen = skb_queue_len(&sd->input_pkt_queue);
		if (qlen) //°Ñ´Óinput_pkt_queueÁ´±íÖĞµÄÈ¡³öµÄËùÓĞskbĞÅÏ¢Ìí¼Óµ½process_queueÖĞ£¬È»ºó´ÓĞÂ³õÊ¼»¯input_pkt_queue£¬¼ûprocess_backlog
			skb_queue_splice_tail_init(&sd->input_pkt_queue,
				&sd->process_queue);/* °Ñsd->input_pkt_queueÁ´±íÖĞµÄ½ÚµãÌí¼Óµ½sd->process_queueµÄÎ²²¿¡£ È»ºó³õÊ¼»¯sd->input_pkt_queueÁ´±í */

		if (qlen < quota - work) {
			/*
			 * Inline a custom version of __napi_complete().
			 * only current cpu owns and manipulates this napi,
			 * and NAPI_STATE_SCHED is the only possible flag set on backlog.
			 * we can use a plain write instead of clear_bit(),
			 * and we dont need an smp_mb() memory barrier.
			 */
			list_del(&napi->poll_list);
			napi->state = 0;

			quota = work + qlen;
		}
		rps_unlock(sd);
	}
	local_irq_enable();

	return work;
}

/**
 * __napi_schedule - schedule for receive
 * @n: entry to schedule
 *
 * The entry's receive function will be scheduled to run
 */
void __napi_schedule(struct napi_struct *n)
{
	unsigned long flags;

	local_irq_save(flags);
	____napi_schedule(&__get_cpu_var(softnet_data), n);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(__napi_schedule);

void __napi_complete(struct napi_struct *n)
{
	BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));
	BUG_ON(n->gro_list);

	list_del(&n->poll_list);
	smp_mb__before_clear_bit();
	clear_bit(NAPI_STATE_SCHED, &n->state);
}
EXPORT_SYMBOL(__napi_complete);

void napi_complete(struct napi_struct *n)
{
	unsigned long flags;

	/*
	 * don't let napi dequeue from the cpu poll list
	 * just in case its running on a different cpu
	 */
	if (unlikely(test_bit(NAPI_STATE_NPSVC, &n->state)))
		return;

	napi_gro_flush(n);
	local_irq_save(flags);
	__napi_complete(n);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(napi_complete);

void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int), int weight)
{
	INIT_LIST_HEAD(&napi->poll_list);
	napi->gro_count = 0;
	napi->gro_list = NULL;
	napi->skb = NULL;
	napi->poll = poll;
	napi->weight = weight;
	list_add(&napi->dev_list, &dev->napi_list);
	napi->dev = dev;
#ifdef CONFIG_NETPOLL
	spin_lock_init(&napi->poll_lock);
	napi->poll_owner = -1;
#endif
	set_bit(NAPI_STATE_SCHED, &napi->state);
}
EXPORT_SYMBOL(netif_napi_add);

void netif_napi_del(struct napi_struct *napi)
{
	struct sk_buff *skb, *next;

	list_del_init(&napi->dev_list);
	napi_free_frags(napi);

	for (skb = napi->gro_list; skb; skb = next) {
		next = skb->next;
		skb->next = NULL;
		kfree_skb(skb);
	}

	napi->gro_list = NULL;
	napi->gro_count = 0;
}
EXPORT_SYMBOL(netif_napi_del);

//±¨ÎÄ½ÓÊÕÈíÖĞ¶ÏµÄ´¦Àíº¯Êınet_rx_actionÏê½â£º
/*
½ÓÊÕÊı¾İ°üµÄÏÂ°ë²¿´¦ÀíÁ÷³ÌÎª£º
net_rx_action // ÈíÖĞ¶Ï //net_rx_actionÖĞ»á¶Ô°üµÄ¸öÊı£¬ÒÔ¼°ÈíÖĞ¶Ï´¦ÀíÊ±¼ä½øĞĞÏŞÖÆ
    |--> process_backlog() // Ä¬ÈÏpoll
               |--> __netif_receive_skb() // L2´¦Àíº¯Êı
                            |--> ip_rcv() // L3Èë¿Ú

*///open_softirq(NET_RX_SOFTIRQ, net_rx_action);,ÔÚnet_dev_initÖĞ×¢²á¸ÃÈí¼şÖĞ¶Ï
/*
//·ÇNAPI·½Ê½£¬´ÓÇı¶¯Ó²¼şÖĞ¶ÏÖĞµ÷ÓÃÕâ¸önetif_rxº¯Êı£¬¶øNAPI·½Ê½´ÓÓ²¼şÖĞ¶ÏÖĞµ÷ÓÃnapi_schedule, 
 //²Î¿¼ Êı¾İ°ü½ÓÊÕÏµÁĞ ¡ª NAPIµÄÔ­ÀíºÍÊµÏÖ http://blog.csdn.net/zhangskd/article/details/21627963
 //²»¹ÜNAPI»¹ÊÇ·ÇNAPI×îÖÕ¶¼µ÷ÓÃnet_rx_action
*/

/*
            ·ÇNAPI·½Ê½                                              NAPI·½Ê½(NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£Ê¹ÓÃ²Î¿¼:Íø¿ÚÊÕ·¢°üÒÔ¼°NAPI_huwei_10_ĞÂÀË²©¿Í.htm)

                                        IRQ
                                         |
                  _______________________|_____________________________
                  |                                                     |
             netif_rx                                            napi_schedule
 ÉÏ°ë²¿           |                                                     | 
             enqueue_to_backlog                                  __napi_schedule
                  |                                                     |           
            skb¼ÓÈëinput_pkt_queuemÖĞ                           napi_struct¼ÓÈëpoll_listÖĞ
            softnet_data->backlog¼ÓÈëpoll_listÖĞ                                      | 
                   |____________________________________________________| 
                                             |
                                        net_rx_action
ÏÂ°ë²¿                                       |
                      _______________________|_____________________________
                      |                                                     |
            process_backlog->__netif_receive_skb                Çı¶¯poll·½·¨->napi_gro_receive->netif_receive_skb->__netif_receive_skb

*/

static void net_rx_action(struct softirq_action *h) //½ÓÊÕ¹ı³ÌÄÄĞ©º¯Êı´¦ÓÚÉÏ°ë²¿£¬ÄÄĞ©º¯Êı´¦ÓÚÏÂ°ë²¿£¬²Î¿¼ Êı¾İ°ü½ÓÊÕÏµÁĞ ¡ª NAPIµÄÔ­ÀíºÍÊµÏÖ http://blog.csdn.net/zhangskd/article/details/21627963
{
	struct softnet_data *sd = &__get_cpu_var(softnet_data);
	unsigned long time_limit = jiffies + 2;  /*ÉèÖÃÈíÖĞ¶Ï´¦Àí³ÌĞòÒ»´ÎÔÊĞíµÄ×î´óÖ´ĞĞÊ±¼äÎª2¸öjiffies*/
	int budget = netdev_budget; /*ÉèÖÃÈíÖĞ¶Ï½ÓÊÕº¯ÊıÒ»´Î×î¶à´¦ÀíµÄ±¨ÎÄ¸öÊıÎª 300 */
	void *have;

	local_irq_disable();

    /*  
    NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£
    ·ÇNAPIµÄnapi_struct½á¹¹ÊÇÄ¬ÈÏµÄ£¬Ò²¾ÍÊÇper cpuµÄsoftnet_data>backlog£¬Æğpoll¹³×Óº¯ÊıÎªprocess_backlog
    */
	while (!list_empty(&sd->poll_list)) {
		struct napi_struct *n;
		int work, weight;

		/* If softirq window is exhuasted then punt.
		 * Allow this to run for 2 jiffies since which will allow
		 * an average latency of 1.5/HZ.
		 */

		 /*
         /*Èç¹û´¦Àí±¨ÎÄ³¬³öÒ»´Î´¦Àí×î´óµÄ¸öÊı »òÔÊĞíÊ±¼ä³¬¹ı×î´óÊ±¼ä¾ÍÍ£Ö¹Ö´ĞĞ£¬           
         Ìøµ½softnet_break ´¦*/
		 */
		if (unlikely(budget <= 0 || time_after(jiffies, time_limit)))
			goto softnet_break;


        /*
        
        /*Ê¹ÄÜ±¾µØÖĞ¶Ï£¬ÉÏÃæÅĞ¶ÏlistÎª¿ÕÒÑÍê³É£¬ÏÂÃæµ÷ÓÃNAPIµÄÂÖÑ¯º¯ÊıÊÇÔÚÓ²ÖĞ¶Ï¿ªÆôµÄÇé¿öÏÂÖ´ĞĞ*/
		local_irq_enable();

		/* Even though interrupts have been re-enabled, this
		 * access is safe because interrupts can only add new
		 * entries to the tail of this list, and only ->poll()
		 * calls can remove this head entry from the list.
		 */

		/*
    
        /* È¡µÃsoftnet_data pool_list Á´±íÉÏµÄÒ»¸önapi,        
        ¼´Ê¹ÏÖÔÚÓ²ÖĞ¶ÏÇÀÕ¼ÈíÖĞ¶Ï£¬»á°ÑÒ»¸önapi¹Òµ½pool_listµÄÎ²¶Ë            
        ÈíÖĞ¶ÏÖ»»á´Ópool_list Í·²¿ÒÆ³ıÒ»¸öpool_list£¬ÕâÑù²»´æÔÚÁÙ½çÇø*/
		n = list_first_entry(&sd->poll_list, struct napi_struct, poll_list);

		have = netpoll_poll_lock(n);

		weight = n->weight;  /*ÓÃweighe ¼ÇÂ¼napi Ò»´ÎÂÖÑ¯ÔÊĞí´¦ÀíµÄ×î´ó±¨ÎÄÊı*/

		/* This NAPI_STATE_SCHED test is for avoiding a race
		 * with netpoll's poll_napi().  Only the entity which
		 * obtains the lock and sees NAPI_STATE_SCHED set will
		 * actually make the ->poll() call.  Therefore we avoid
		 * accidently calling ->poll() when NAPI is not scheduled.
		 */
		work = 0;  /* work ¼ÇÂ¼Ò»¸önapi×Ü¹²´¦ÀíµÄ±¨ÎÄÊı*/
		
		if (test_bit(NAPI_STATE_SCHED, &n->state)) {/*Èç¹ûÈ¡µÃµÄnapi×´Ì¬ÊÇ±»µ÷¶ÈµÄ£¬¾ÍÖ´ĞĞnapiµÄÂÖÑ¯´¦Àíº¯Êı*/
            /*  
                    NAPIµÄnapi_structÊÇ×Ô¼º¹¹ÔìµÄ£¬¸Ã½á¹¹ÉÏµÄpoll¹³×Óº¯ÊıÒ²ÊÇ×Ô¼º¶¨ÒåµÄ¡£
                    ·ÇNAPIµÄnapi_struct½á¹¹ÊÇÄ¬ÈÏµÄ£¬Ò²¾ÍÊÇper cpuµÄsoftnet_data>backlog£¬Æğpoll¹³×Óº¯ÊıÎªprocess_backlog
                */
			work = n->poll(n, weight);
			trace_napi_poll(n);
		}

		WARN_ON_ONCE(work > weight);

		budget -= work;  /*Ô¤Ëã¼õÈ¥ÒÑ¾­´¦ÀíµÄ±¨ÎÄÊı*/


        /*
            
        /*½ûÖ¹±¾µØCPU µÄÖĞ¶Ï£¬ÏÂÃæ»áÓĞ°ÑÃ»Ö´ĞĞÍêµÄNAPI¹Òµ½softnet_data      
        Î²²¿µÄ²Ù×÷£¬ºÍÓ²ÖĞ¶Ï´æÔÚÁÙ½çÇø¡£Í¬Ê±whileÑ­»·Ê±ÅĞ¶ÏlistÊÇ·ñÎª¿ÕÊ±Ò²Òª½ûÖ¹Ó²ÖĞ¶ÏÇÀÕ¼*/
		local_irq_disable();

		/* Drivers must not modify the NAPI state if they
		 * consume the entire weight.  In such cases this code
		 * still "owns" the NAPI instance and therefore can
		 * move the instance around on the list at-will.
		 */

		/*
            
        /*Èç¹ûnapi Ò»´ÎÂÖÑ¯´¦ÀíµÄ±¨ÎÄÊıÕıºÃµÈÓÚÔÊĞí´¦ÀíµÄ×î´óÊı,ËµÃ÷Ò»´ÎÂÖÑ¯Ã»´¦ÀíÍêÈ«²¿ĞèÒª´¦ÀíµÄ±¨ÎÄ*/
		if (unlikely(work == weight)) {
			if (unlikely(napi_disable_pending(n))) { /*Èç¹ûnapiÒÑ¾­±»½ûÓÃ£¬¾Í°Ñnapi ´Ó softnet_data µÄpool_list ÉÏÒÆ³ı*/
				local_irq_enable();
				napi_complete(n);
				local_irq_disable();
			} else  /*·ñÔò£¬°Ñnapi ÒÆµ½ pool_list µÄÎ²¶Ë*/
				list_move_tail(&n->poll_list, &sd->poll_list);
		}

		netpoll_poll_unlock(have);
	}


/*Èç¹û´¦ÀíÊ±¼ä³¬Ê±£¬»ò´¦ÀíµÄ±¨ÎÄÊıµ½ÁË×î¶àÔÊĞí´¦ÀíµÄ¸öÊı£¬ËµÃ÷»¹ÓĞnapi ÉÏÓĞ±¨ÎÄĞèÒª´¦Àí£¬µ÷¶ÈÈíÖĞ¶Ï¡£·ñÔò£¬
ËµÃ÷Õâ´ÎÈíÖĞ¶Ï´¦ÀíÍêÈ«²¿µÄnapiÉÏµÄĞèÒª´¦ÀíµÄ±¨ÎÄ£¬²»ÔÙĞèÒªµ÷¶ÈÈíÖĞ¶ÏÁË*/

out:
	net_rps_action_and_irq_enable(sd);

#ifdef CONFIG_NET_DMA
	/*
	 * There may not be any more sk_buffs coming right now, so push
	 * any pending DMA copies to hardware
	 */
	dma_issue_pending_all();
#endif

	return;

softnet_break: //¶ÁÈ¡Ê±¼äµ½»òÕß´ÓÒ»¸önapiÖĞ¶ÁÈ¡µÄ±¨ÎÄÊı´ïµ½×î´óÖµ
	sd->time_squeeze++;
	__raise_softirq_irqoff(NET_RX_SOFTIRQ);
	goto out;
}

static gifconf_func_t *gifconf_list[NPROTO];

/**
 *	register_gifconf	-	register a SIOCGIF handler
 *	@family: Address family
 *	@gifconf: Function handler
 *
 *	Register protocol dependent address dumping routines. The handler
 *	that is passed must not be freed or reused until it has been replaced
 *	by another handler.
 */
int register_gifconf(unsigned int family, gifconf_func_t *gifconf)
{
	if (family >= NPROTO)
		return -EINVAL;
	gifconf_list[family] = gifconf;
	return 0;
}
EXPORT_SYMBOL(register_gifconf);


/*
 *	Map an interface index to its name (SIOCGIFNAME)
 */

/*
 *	We need this ioctl for efficient implementation of the
 *	if_indextoname() function required by the IPv6 API.  Without
 *	it, we would have to search all the interfaces to find a
 *	match.  --pb
 */

static int dev_ifname(struct net *net, struct ifreq __user *arg)
{
	struct net_device *dev;
	struct ifreq ifr;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	rcu_read_lock();
	dev = dev_get_by_index_rcu(net, ifr.ifr_ifindex);
	if (!dev) {
		rcu_read_unlock();
		return -ENODEV;
	}

	strcpy(ifr.ifr_name, dev->name);
	rcu_read_unlock();

	if (copy_to_user(arg, &ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

/*
 *	Perform a SIOCGIFCONF call. This structure will change
 *	size eventually, and there is nothing I can do about it.
 *	Thus we will need a 'compatibility mode'.
 */

static int dev_ifconf(struct net *net, char __user *arg)
{
	struct ifconf ifc;
	struct net_device *dev;
	char __user *pos;
	int len;
	int total;
	int i;

	/*
	 *	Fetch the caller's info block.
	 */

	if (copy_from_user(&ifc, arg, sizeof(struct ifconf)))
		return -EFAULT;

	pos = ifc.ifc_buf;
	len = ifc.ifc_len;

	/*
	 *	Loop over the interfaces, and write an info block for each.
	 */

	total = 0;
	for_each_netdev(net, dev) {
		for (i = 0; i < NPROTO; i++) {
			if (gifconf_list[i]) {
				int done;
				if (!pos)
					done = gifconf_list[i](dev, NULL, 0);
				else
					done = gifconf_list[i](dev, pos + total,
							       len - total);
				if (done < 0)
					return -EFAULT;
				total += done;
			}
		}
	}

	/*
	 *	All done.  Write the updated control block back to the caller.
	 */
	ifc.ifc_len = total;

	/*
	 * 	Both BSD and Solaris return 0 here, so we do too.
	 */
	return copy_to_user(arg, &ifc, sizeof(struct ifconf)) ? -EFAULT : 0;
}

#ifdef CONFIG_PROC_FS
/*
 *	This is invoked by the /proc filesystem handler to display a device
 *	in detail.
 */
void *dev_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	struct net *net = seq_file_net(seq);
	loff_t off;
	struct net_device *dev;

	rcu_read_lock();
	if (!*pos)
		return SEQ_START_TOKEN;

	off = 1;
	for_each_netdev_rcu(net, dev)
		if (off++ == *pos)
			return dev;

	return NULL;
}

void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct net_device *dev = (v == SEQ_START_TOKEN) ?
				  first_net_device(seq_file_net(seq)) :
				  next_net_device((struct net_device *)v);

	++*pos;
	return rcu_dereference(dev);
}

void dev_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static void dev_seq_printf_stats(struct seq_file *seq, struct net_device *dev)
{
	const struct net_device_stats *stats = dev_get_stats(dev);

	seq_printf(seq, "%6s: %7lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu "
		   "%8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu\n",
		   dev->name, stats->rx_bytes, stats->rx_packets,
		   stats->rx_errors,
		   stats->rx_dropped + stats->rx_missed_errors,
		   stats->rx_fifo_errors,
		   stats->rx_length_errors + stats->rx_over_errors +
		    stats->rx_crc_errors + stats->rx_frame_errors,
		   stats->rx_compressed, stats->multicast,
		   stats->tx_bytes, stats->tx_packets,
		   stats->tx_errors, stats->tx_dropped,
		   stats->tx_fifo_errors, stats->collisions,
		   stats->tx_carrier_errors +
		    stats->tx_aborted_errors +
		    stats->tx_window_errors +
		    stats->tx_heartbeat_errors,
		   stats->tx_compressed);
}

/*
 *	Called from the PROCfs module. This now uses the new arbitrary sized
 *	/proc/net interface to create /proc/net/dev
 */
static int dev_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Inter-|   Receive                            "
			      "                    |  Transmit\n"
			      " face |bytes    packets errs drop fifo frame "
			      "compressed multicast|bytes    packets errs "
			      "drop fifo colls carrier compressed\n");
	else
		dev_seq_printf_stats(seq, v);
	return 0;
}

static struct softnet_data *softnet_get_online(loff_t *pos)
{
	struct softnet_data *sd = NULL;

	while (*pos < nr_cpu_ids)
		if (cpu_online(*pos)) {
			sd = &per_cpu(softnet_data, *pos);
			break;
		} else
			++*pos;
	return sd;
}

static void *softnet_seq_start(struct seq_file *seq, loff_t *pos)
{
	return softnet_get_online(pos);
}

static void *softnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return softnet_get_online(pos);
}

static void softnet_seq_stop(struct seq_file *seq, void *v)
{
}

static int softnet_seq_show(struct seq_file *seq, void *v)
{
	struct softnet_data *sd = v;

	seq_printf(seq, "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
		   sd->processed, sd->dropped, sd->time_squeeze, 0,
		   0, 0, 0, 0, /* was fastroute */
		   sd->cpu_collision, sd->received_rps);
	return 0;
}

static const struct seq_operations dev_seq_ops = {
	.start = dev_seq_start,
	.next  = dev_seq_next,
	.stop  = dev_seq_stop,
	.show  = dev_seq_show,
};

static int dev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &dev_seq_ops,
			    sizeof(struct seq_net_private));
}

static const struct file_operations dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = dev_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_net,
};

static const struct seq_operations softnet_seq_ops = {
	.start = softnet_seq_start,
	.next  = softnet_seq_next,
	.stop  = softnet_seq_stop,
	.show  = softnet_seq_show,
};

static int softnet_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &softnet_seq_ops);
}

static const struct file_operations softnet_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = softnet_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void *ptype_get_idx(loff_t pos)
{
	struct packet_type *pt = NULL;
	loff_t i = 0;
	int t;

	list_for_each_entry_rcu(pt, &ptype_all, list) {
		if (i == pos)
			return pt;
		++i;
	}

	for (t = 0; t < PTYPE_HASH_SIZE; t++) {
		list_for_each_entry_rcu(pt, &ptype_base[t], list) {
			if (i == pos)
				return pt;
			++i;
		}
	}
	return NULL;
}

static void *ptype_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(RCU)
{
	rcu_read_lock();
	return *pos ? ptype_get_idx(*pos - 1) : SEQ_START_TOKEN;
}

static void *ptype_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct packet_type *pt;
	struct list_head *nxt;
	int hash;

	++*pos;
	if (v == SEQ_START_TOKEN)
		return ptype_get_idx(0);

	pt = v;
	nxt = pt->list.next;
	if (pt->type == htons(ETH_P_ALL)) {
		if (nxt != &ptype_all)
			goto found;
		hash = 0;
		nxt = ptype_base[0].next;
	} else
		hash = ntohs(pt->type) & PTYPE_HASH_MASK;

	while (nxt == &ptype_base[hash]) {
		if (++hash >= PTYPE_HASH_SIZE)
			return NULL;
		nxt = ptype_base[hash].next;
	}
found:
	return list_entry(nxt, struct packet_type, list);
}

static void ptype_seq_stop(struct seq_file *seq, void *v)
	__releases(RCU)
{
	rcu_read_unlock();
}

static int ptype_seq_show(struct seq_file *seq, void *v)
{
	struct packet_type *pt = v;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "Type Device      Function\n");
	else if (pt->dev == NULL || dev_net(pt->dev) == seq_file_net(seq)) {
		if (pt->type == htons(ETH_P_ALL))
			seq_puts(seq, "ALL ");
		else
			seq_printf(seq, "%04x", ntohs(pt->type));

		seq_printf(seq, " %-8s %pF\n",
			   pt->dev ? pt->dev->name : "", pt->func);
	}

	return 0;
}

static const struct seq_operations ptype_seq_ops = {
	.start = ptype_seq_start,
	.next  = ptype_seq_next,
	.stop  = ptype_seq_stop,
	.show  = ptype_seq_show,
};

static int ptype_seq_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &ptype_seq_ops,
			sizeof(struct seq_net_private));
}

static const struct file_operations ptype_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = ptype_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release_net,
};


static int __net_init dev_proc_net_init(struct net *net)
{
	int rc = -ENOMEM;

	if (!proc_net_fops_create(net, "dev", S_IRUGO, &dev_seq_fops))
		goto out;
	if (!proc_net_fops_create(net, "softnet_stat", S_IRUGO, &softnet_seq_fops))
		goto out_dev;
	if (!proc_net_fops_create(net, "ptype", S_IRUGO, &ptype_seq_fops))
		goto out_softnet;

	if (wext_proc_init(net))
		goto out_ptype;
	rc = 0;
out:
	return rc;
out_ptype:
	proc_net_remove(net, "ptype");
out_softnet:
	proc_net_remove(net, "softnet_stat");
out_dev:
	proc_net_remove(net, "dev");
	goto out;
}

static void __net_exit dev_proc_net_exit(struct net *net)
{
	wext_proc_exit(net);

	proc_net_remove(net, "ptype");
	proc_net_remove(net, "softnet_stat");
	proc_net_remove(net, "dev");
}

static struct pernet_operations __net_initdata dev_proc_ops = {
	.init = dev_proc_net_init,
	.exit = dev_proc_net_exit,
};

static int __init dev_proc_init(void)
{
	return register_pernet_subsys(&dev_proc_ops);
}
#else
#define dev_proc_init() 0
#endif	/* CONFIG_PROC_FS */


/**
 *	netdev_set_master	-	set up master/slave pair
 *	@slave: slave device
 *	@master: new master device
 *
 *	Changes the master device of the slave. Pass %NULL to break the
 *	bonding. The caller must hold the RTNL semaphore. On a failure
 *	a negative errno code is returned. On success the reference counts
 *	are adjusted, %RTM_NEWLINK is sent to the routing socket and the
 *	function returns zero.
 */
int netdev_set_master(struct net_device *slave, struct net_device *master)
{
	struct net_device *old = slave->master;

	ASSERT_RTNL();

	if (master) {
		if (old)
			return -EBUSY;
		dev_hold(master);
	}

	slave->master = master;

	if (old) {
		synchronize_net();
		dev_put(old);
	}
	if (master)
		slave->flags |= IFF_SLAVE;
	else
		slave->flags &= ~IFF_SLAVE;

	rtmsg_ifinfo(RTM_NEWLINK, slave, IFF_SLAVE);
	return 0;
}
EXPORT_SYMBOL(netdev_set_master);

static void dev_change_rx_flags(struct net_device *dev, int flags)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if ((dev->flags & IFF_UP) && ops->ndo_change_rx_flags)
		ops->ndo_change_rx_flags(dev, flags);
}

static int __dev_set_promiscuity(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;
	uid_t uid;
	gid_t gid;

	ASSERT_RTNL();

	dev->flags |= IFF_PROMISC;
	dev->promiscuity += inc;
	if (dev->promiscuity == 0) {
		/*
		 * Avoid overflow.
		 * If inc causes overflow, untouch promisc and return error.
		 */
		if (inc < 0)
			dev->flags &= ~IFF_PROMISC;
		else {
			dev->promiscuity -= inc;
			printk(KERN_WARNING "%s: promiscuity touches roof, "
				"set promiscuity failed, promiscuity feature "
				"of device might be broken.\n", dev->name);
			return -EOVERFLOW;
		}
	}
	if (dev->flags != old_flags) {
		printk(KERN_INFO "device %s %s promiscuous mode\n",
		       dev->name, (dev->flags & IFF_PROMISC) ? "entered" :
							       "left");
		if (audit_enabled) {
			current_uid_gid(&uid, &gid);
			audit_log(current->audit_context, GFP_ATOMIC,
				AUDIT_ANOM_PROMISCUOUS,
				"dev=%s prom=%d old_prom=%d auid=%u uid=%u gid=%u ses=%u",
				dev->name, (dev->flags & IFF_PROMISC),
				(old_flags & IFF_PROMISC),
				audit_get_loginuid(current),
				uid, gid,
				audit_get_sessionid(current));
		}

		dev_change_rx_flags(dev, IFF_PROMISC);
	}
	return 0;
}

/**
 *	dev_set_promiscuity	- update promiscuity count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove promiscuity from a device. While the count in the device
 *	remains above zero the interface remains promiscuous. Once it hits zero
 *	the device reverts back to normal filtering operation. A negative inc
 *	value is used to drop promiscuity on the device.
 *	Return 0 if successful or a negative errno code on error.
 */
int dev_set_promiscuity(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;
	int err;

	err = __dev_set_promiscuity(dev, inc);
	if (err < 0)
		return err;
	if (dev->flags != old_flags)
		dev_set_rx_mode(dev);
	return err;
}
EXPORT_SYMBOL(dev_set_promiscuity);

/**
 *	dev_set_allmulti	- update allmulti count on a device
 *	@dev: device
 *	@inc: modifier
 *
 *	Add or remove reception of all multicast frames to a device. While the
 *	count in the device remains above zero the interface remains listening
 *	to all interfaces. Once it hits zero the device reverts back to normal
 *	filtering operation. A negative @inc value is used to drop the counter
 *	when releasing a resource needing all multicasts.
 *	Return 0 if successful or a negative errno code on error.
 */

int dev_set_allmulti(struct net_device *dev, int inc)
{
	unsigned short old_flags = dev->flags;

	ASSERT_RTNL();

	dev->flags |= IFF_ALLMULTI;
	dev->allmulti += inc;
	if (dev->allmulti == 0) {
		/*
		 * Avoid overflow.
		 * If inc causes overflow, untouch allmulti and return error.
		 */
		if (inc < 0)
			dev->flags &= ~IFF_ALLMULTI;
		else {
			dev->allmulti -= inc;
			printk(KERN_WARNING "%s: allmulti touches roof, "
				"set allmulti failed, allmulti feature of "
				"device might be broken.\n", dev->name);
			return -EOVERFLOW;
		}
	}
	if (dev->flags ^ old_flags) {
		dev_change_rx_flags(dev, IFF_ALLMULTI);
		dev_set_rx_mode(dev);
	}
	return 0;
}
EXPORT_SYMBOL(dev_set_allmulti);

/*
 *	Upload unicast and multicast address lists to device and
 *	configure RX filtering. When the device doesn't support unicast
 *	filtering it is put in promiscuous mode while unicast addresses
 *	are present.
 */
void __dev_set_rx_mode(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	/* dev_open will call this function so the list will stay sane. */
	if (!(dev->flags&IFF_UP))
		return;

	if (!netif_device_present(dev))
		return;

	if (ops->ndo_set_rx_mode)
		ops->ndo_set_rx_mode(dev);
	else {
		/* Unicast addresses changes may only happen under the rtnl,
		 * therefore calling __dev_set_promiscuity here is safe.
		 */
		if (!netdev_uc_empty(dev) && !dev->uc_promisc) {
			__dev_set_promiscuity(dev, 1);
			dev->uc_promisc = 1;
		} else if (netdev_uc_empty(dev) && dev->uc_promisc) {
			__dev_set_promiscuity(dev, -1);
			dev->uc_promisc = 0;
		}

		if (ops->ndo_set_multicast_list)
			ops->ndo_set_multicast_list(dev);
	}
}

void dev_set_rx_mode(struct net_device *dev)
{
	netif_addr_lock_bh(dev);
	__dev_set_rx_mode(dev);
	netif_addr_unlock_bh(dev);
}

/**
 *	dev_get_flags - get flags reported to userspace
 *	@dev: device
 *
 *	Get the combination of flag bits exported through APIs to userspace.
 */
unsigned dev_get_flags(const struct net_device *dev)
{
	unsigned flags;

	flags = (dev->flags & ~(IFF_PROMISC |
				IFF_ALLMULTI |
				IFF_RUNNING |
				IFF_LOWER_UP |
				IFF_DORMANT)) |
		(dev->gflags & (IFF_PROMISC |
				IFF_ALLMULTI));

	if (netif_running(dev)) {
		if (netif_oper_up(dev))
			flags |= IFF_RUNNING;
		if (netif_carrier_ok(dev))
			flags |= IFF_LOWER_UP;
		if (netif_dormant(dev))
			flags |= IFF_DORMANT;
	}

	return flags;
}
EXPORT_SYMBOL(dev_get_flags);

int __dev_change_flags(struct net_device *dev, unsigned int flags)
{
	int old_flags = dev->flags;
	int ret;

	ASSERT_RTNL();

	/*
	 *	Set the flags on our device.
	 */

	dev->flags = (flags & (IFF_DEBUG | IFF_NOTRAILERS | IFF_NOARP |
			       IFF_DYNAMIC | IFF_MULTICAST | IFF_PORTSEL |
			       IFF_AUTOMEDIA)) |
		     (dev->flags & (IFF_UP | IFF_VOLATILE | IFF_PROMISC |
				    IFF_ALLMULTI));

	/*
	 *	Load in the correct multicast list now the flags have changed.
	 */

	if ((old_flags ^ flags) & IFF_MULTICAST)
		dev_change_rx_flags(dev, IFF_MULTICAST);

	dev_set_rx_mode(dev);

	/*
	 *	Have we downed the interface. We handle IFF_UP ourselves
	 *	according to user attempts to set it, rather than blindly
	 *	setting it.
	 */

	ret = 0;
	if ((old_flags ^ flags) & IFF_UP) {	/* Bit is different  ? */
		ret = ((old_flags & IFF_UP) ? __dev_close : __dev_open)(dev);

		if (!ret)
			dev_set_rx_mode(dev);
	}

	if ((flags ^ dev->gflags) & IFF_PROMISC) {
		int inc = (flags & IFF_PROMISC) ? 1 : -1;

		dev->gflags ^= IFF_PROMISC;
		dev_set_promiscuity(dev, inc);
	}

	/* NOTE: order of synchronization of IFF_PROMISC and IFF_ALLMULTI
	   is important. Some (broken) drivers set IFF_PROMISC, when
	   IFF_ALLMULTI is requested not asking us and not reporting.
	 */
	if ((flags ^ dev->gflags) & IFF_ALLMULTI) {
		int inc = (flags & IFF_ALLMULTI) ? 1 : -1;

		dev->gflags ^= IFF_ALLMULTI;
		dev_set_allmulti(dev, inc);
	}

	return ret;
}

void __dev_notify_flags(struct net_device *dev, unsigned int old_flags)
{
	unsigned int changes = dev->flags ^ old_flags;

	if (changes & IFF_UP) {
		if (dev->flags & IFF_UP)
			call_netdevice_notifiers(NETDEV_UP, dev);
		else
			call_netdevice_notifiers(NETDEV_DOWN, dev);
	}

	if (dev->flags & IFF_UP &&
	    (changes & ~(IFF_UP | IFF_PROMISC | IFF_ALLMULTI | IFF_VOLATILE)))
		call_netdevice_notifiers(NETDEV_CHANGE, dev);
}

/**
 *	dev_change_flags - change device settings
 *	@dev: device
 *	@flags: device state flags
 *
 *	Change settings on device based state flags. The flags are
 *	in the userspace exported format.
 */
int dev_change_flags(struct net_device *dev, unsigned flags)
{
	int ret, changes;
	int old_flags = dev->flags;

	ret = __dev_change_flags(dev, flags);
	if (ret < 0)
		return ret;

	changes = old_flags ^ dev->flags;
	if (changes)
		rtmsg_ifinfo(RTM_NEWLINK, dev, changes);

	__dev_notify_flags(dev, old_flags);
	return ret;
}
EXPORT_SYMBOL(dev_change_flags);

/**
 *	dev_set_mtu - Change maximum transfer unit
 *	@dev: device
 *	@new_mtu: new transfer unit
 *
 *	Change the maximum transfer size of the network device.
 */
int dev_set_mtu(struct net_device *dev, int new_mtu)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int err;

	if (new_mtu == dev->mtu)
		return 0;

	/*	MTU must be positive.	 */
	if (new_mtu < 0)
		return -EINVAL;

	if (!netif_device_present(dev))
		return -ENODEV;

	err = 0;
	if (ops->ndo_change_mtu)
		err = ops->ndo_change_mtu(dev, new_mtu);
	else
		dev->mtu = new_mtu;

	if (!err && dev->flags & IFF_UP)
		call_netdevice_notifiers(NETDEV_CHANGEMTU, dev);
	return err;
}
EXPORT_SYMBOL(dev_set_mtu);

/**
 *	dev_set_mac_address - Change Media Access Control Address
 *	@dev: device
 *	@sa: new address
 *
 *	Change the hardware (MAC) address of the device
 */
int dev_set_mac_address(struct net_device *dev, struct sockaddr *sa)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int err;

	if (!ops->ndo_set_mac_address)
		return -EOPNOTSUPP;
	if (sa->sa_family != dev->type)
		return -EINVAL;
	if (!netif_device_present(dev))
		return -ENODEV;
	err = ops->ndo_set_mac_address(dev, sa);
	if (!err)
		call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);
	return err;
}
EXPORT_SYMBOL(dev_set_mac_address);

/*
 *	Perform the SIOCxIFxxx calls, inside rcu_read_lock()
 */
static int dev_ifsioc_locked(struct net *net, struct ifreq *ifr, unsigned int cmd)
{
	int err;
	struct net_device *dev = dev_get_by_name_rcu(net, ifr->ifr_name);

	if (!dev)
		return -ENODEV;

	switch (cmd) {
	case SIOCGIFFLAGS:	/* Get interface flags */
		ifr->ifr_flags = (short) dev_get_flags(dev);
		return 0;

	case SIOCGIFMETRIC:	/* Get the metric on the interface
				   (currently unused) */
		ifr->ifr_metric = 0;
		return 0;

	case SIOCGIFMTU:	/* Get the MTU of a device */
		ifr->ifr_mtu = dev->mtu;
		return 0;

	case SIOCGIFHWADDR:
		if (!dev->addr_len)
			memset(ifr->ifr_hwaddr.sa_data, 0, sizeof ifr->ifr_hwaddr.sa_data);
		else
			memcpy(ifr->ifr_hwaddr.sa_data, dev->dev_addr,
			       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
		ifr->ifr_hwaddr.sa_family = dev->type;
		return 0;

	case SIOCGIFSLAVE:
		err = -EINVAL;
		break;

	case SIOCGIFMAP:
		ifr->ifr_map.mem_start = dev->mem_start;
		ifr->ifr_map.mem_end   = dev->mem_end;
		ifr->ifr_map.base_addr = dev->base_addr;
		ifr->ifr_map.irq       = dev->irq;
		ifr->ifr_map.dma       = dev->dma;
		ifr->ifr_map.port      = dev->if_port;
		return 0;

	case SIOCGIFINDEX:
		ifr->ifr_ifindex = dev->ifindex;
		return 0;

	case SIOCGIFTXQLEN:
		ifr->ifr_qlen = dev->tx_queue_len;
		return 0;

	default:
		/* dev_ioctl() should ensure this case
		 * is never reached
		 */
		WARN_ON(1);
		err = -EINVAL;
		break;

	}
	return err;
}

/*
 *	Perform the SIOCxIFxxx calls, inside rtnl_lock()
 */
static int dev_ifsioc(struct net *net, struct ifreq *ifr, unsigned int cmd)
{
	int err;
	struct net_device *dev = __dev_get_by_name(net, ifr->ifr_name);
	const struct net_device_ops *ops;

	if (!dev)
		return -ENODEV;

	ops = dev->netdev_ops;

	switch (cmd) {
	case SIOCSIFFLAGS:	/* Set interface flags */
		return dev_change_flags(dev, ifr->ifr_flags);

	case SIOCSIFMETRIC:	/* Set the metric on the interface
				   (currently unused) */
		return -EOPNOTSUPP;

	case SIOCSIFMTU:	/* Set the MTU of a device */
		return dev_set_mtu(dev, ifr->ifr_mtu);

	case SIOCSIFHWADDR:
		return dev_set_mac_address(dev, &ifr->ifr_hwaddr);

	case SIOCSIFHWBROADCAST:
		if (ifr->ifr_hwaddr.sa_family != dev->type)
			return -EINVAL;
		memcpy(dev->broadcast, ifr->ifr_hwaddr.sa_data,
		       min(sizeof ifr->ifr_hwaddr.sa_data, (size_t) dev->addr_len));
		call_netdevice_notifiers(NETDEV_CHANGEADDR, dev);
		return 0;

	case SIOCSIFMAP:
		if (ops->ndo_set_config) {
			if (!netif_device_present(dev))
				return -ENODEV;
			return ops->ndo_set_config(dev, &ifr->ifr_map);
		}
		return -EOPNOTSUPP;

	case SIOCADDMULTI:
		if ((!ops->ndo_set_multicast_list && !ops->ndo_set_rx_mode) ||
		    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
			return -EINVAL;
		if (!netif_device_present(dev))
			return -ENODEV;
		return dev_mc_add_global(dev, ifr->ifr_hwaddr.sa_data);

	case SIOCDELMULTI:
		if ((!ops->ndo_set_multicast_list && !ops->ndo_set_rx_mode) ||
		    ifr->ifr_hwaddr.sa_family != AF_UNSPEC)
			return -EINVAL;
		if (!netif_device_present(dev))
			return -ENODEV;
		return dev_mc_del_global(dev, ifr->ifr_hwaddr.sa_data);

	case SIOCSIFTXQLEN:
		if (ifr->ifr_qlen < 0)
			return -EINVAL;
		dev->tx_queue_len = ifr->ifr_qlen;
		return 0;

	case SIOCSIFNAME:
		ifr->ifr_newname[IFNAMSIZ-1] = '\0';
		return dev_change_name(dev, ifr->ifr_newname);

	/*
	 *	Unknown or private ioctl
	 */
	default:
		if ((cmd >= SIOCDEVPRIVATE &&
		    cmd <= SIOCDEVPRIVATE + 15) ||
		    cmd == SIOCBONDENSLAVE ||
		    cmd == SIOCBONDRELEASE ||
		    cmd == SIOCBONDSETHWADDR ||
		    cmd == SIOCBONDSLAVEINFOQUERY ||
		    cmd == SIOCBONDINFOQUERY ||
		    cmd == SIOCBONDCHANGEACTIVE ||
		    cmd == SIOCGMIIPHY ||
		    cmd == SIOCGMIIREG ||
		    cmd == SIOCSMIIREG ||
		    cmd == SIOCBRADDIF ||
		    cmd == SIOCBRDELIF ||
		    cmd == SIOCSHWTSTAMP ||
		    cmd == SIOCWANDEV) {
			err = -EOPNOTSUPP;
			if (ops->ndo_do_ioctl) {
				if (netif_device_present(dev))
					err = ops->ndo_do_ioctl(dev, ifr, cmd);
				else
					err = -ENODEV;
			}
		} else
			err = -EINVAL;

	}
	return err;
}

/*
 *	This function handles all "interface"-type I/O control requests. The actual
 *	'doing' part of this is dev_ifsioc above.
 */

/**
 *	dev_ioctl	-	network device ioctl
 *	@net: the applicable net namespace
 *	@cmd: command to issue
 *	@arg: pointer to a struct ifreq in user space
 *
 *	Issue ioctl functions to devices. This is normally called by the
 *	user space syscall interfaces but can sometimes be useful for
 *	other purposes. The return value is the return from the syscall if
 *	positive or a negative errno code on error.
 */

int dev_ioctl(struct net *net, unsigned int cmd, void __user *arg)
{
	struct ifreq ifr;
	int ret;
	char *colon;

	/* One special case: SIOCGIFCONF takes ifconf argument
	   and requires shared lock, because it sleeps writing
	   to user space.
	 */

	if (cmd == SIOCGIFCONF) {
		rtnl_lock();
		ret = dev_ifconf(net, (char __user *) arg);
		rtnl_unlock();
		return ret;
	}
	if (cmd == SIOCGIFNAME)
		return dev_ifname(net, (struct ifreq __user *)arg);

	if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
		return -EFAULT;

	ifr.ifr_name[IFNAMSIZ-1] = 0;

	colon = strchr(ifr.ifr_name, ':');
	if (colon)
		*colon = 0;

	/*
	 *	See which interface the caller is talking about.
	 */

	switch (cmd) {
	/*
	 *	These ioctl calls:
	 *	- can be done by all.
	 *	- atomic and do not require locking.
	 *	- return a value
	 */
	case SIOCGIFFLAGS:
	case SIOCGIFMETRIC:
	case SIOCGIFMTU:
	case SIOCGIFHWADDR:
	case SIOCGIFSLAVE:
	case SIOCGIFMAP:
	case SIOCGIFINDEX:
	case SIOCGIFTXQLEN:
		dev_load(net, ifr.ifr_name);
		rcu_read_lock();
		ret = dev_ifsioc_locked(net, &ifr, cmd);
		rcu_read_unlock();
		if (!ret) {
			if (colon)
				*colon = ':';
			if (copy_to_user(arg, &ifr,
					 sizeof(struct ifreq)))
				ret = -EFAULT;
		}
		return ret;

	case SIOCETHTOOL:
		dev_load(net, ifr.ifr_name);
		rtnl_lock();
		ret = dev_ethtool(net, &ifr);
		rtnl_unlock();
		if (!ret) {
			if (colon)
				*colon = ':';
			if (copy_to_user(arg, &ifr,
					 sizeof(struct ifreq)))
				ret = -EFAULT;
		}
		return ret;

	/*
	 *	These ioctl calls:
	 *	- require superuser power.
	 *	- require strict serialization.
	 *	- return a value
	 */
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSIFNAME:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		dev_load(net, ifr.ifr_name);
		rtnl_lock();
		ret = dev_ifsioc(net, &ifr, cmd);
		rtnl_unlock();
		if (!ret) {
			if (colon)
				*colon = ':';
			if (copy_to_user(arg, &ifr,
					 sizeof(struct ifreq)))
				ret = -EFAULT;
		}
		return ret;

	/*
	 *	These ioctl calls:
	 *	- require superuser power.
	 *	- require strict serialization.
	 *	- do not return a value
	 */
	case SIOCSIFFLAGS:
	case SIOCSIFMETRIC:
	case SIOCSIFMTU:
	case SIOCSIFMAP:
	case SIOCSIFHWADDR:
	case SIOCSIFSLAVE:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCSIFHWBROADCAST:
	case SIOCSIFTXQLEN:
	case SIOCSMIIREG:
	case SIOCBONDENSLAVE:
	case SIOCBONDRELEASE:
	case SIOCBONDSETHWADDR:
	case SIOCBONDCHANGEACTIVE:
	case SIOCBRADDIF:
	case SIOCBRDELIF:
	case SIOCSHWTSTAMP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		/* fall through */
	case SIOCBONDSLAVEINFOQUERY:
	case SIOCBONDINFOQUERY:
		dev_load(net, ifr.ifr_name);
		rtnl_lock();
		ret = dev_ifsioc(net, &ifr, cmd);
		rtnl_unlock();
		return ret;

	case SIOCGIFMEM:
		/* Get the per device memory space. We can add this but
		 * currently do not support it */
	case SIOCSIFMEM:
		/* Set the per device memory buffer space.
		 * Not applicable in our case */
	case SIOCSIFLINK:
		return -EINVAL;

	/*
	 *	Unknown or private ioctl.
	 */
	default:
		if (cmd == SIOCWANDEV ||
		    (cmd >= SIOCDEVPRIVATE &&
		     cmd <= SIOCDEVPRIVATE + 15)) {
			dev_load(net, ifr.ifr_name);
			rtnl_lock();
			ret = dev_ifsioc(net, &ifr, cmd);
			rtnl_unlock();
			if (!ret && copy_to_user(arg, &ifr,
						 sizeof(struct ifreq)))
				ret = -EFAULT;
			return ret;
		}
		/* Take care of Wireless Extensions */
		if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST)
			return wext_handle_ioctl(net, &ifr, cmd, arg);
		return -EINVAL;
	}
}


/**
 *	dev_new_index	-	allocate an ifindex
 *	@net: the applicable net namespace
 *
 *	Returns a suitable unique value for a new device interface
 *	number.  The caller must hold the rtnl semaphore or the
 *	dev_base_lock to be sure it remains unique.
 *///ÎªÉè±¸·ÖÅäÒ»¸öÎ¨Ò»Ë÷ÒıºÅºÍÒ»¸öÓÃÓÚĞéÄâËíµÀÉè±¸µÄÎ¨Ò»±êÊ¾ºÅ
static int dev_new_index(struct net *net)
{
	static int ifindex;
	for (;;) {
		if (++ifindex <= 0)
			ifindex = 1;
		if (!__dev_get_by_index(net, ifindex))
			return ifindex;
	}
}

/* Delayed registration/unregisteration */
//static LIST_HEAD(net_todo_list);
struct list_head net_todo_list = LIST_HEAD_INIT(net_todo_list);//×îÖÕÓÉnetdev_run_todoÖ´ĞĞ¸ÃÁ´±íÖĞµÄdev¡£¸ÃÁ´±íÊÇÅĞ¶ÏdevµÄÒıÓÃ¼ÆÊırefcntÊÇ·ñÎª0

//Èç¹ûÎª0ÔòÖ±½Óµ÷ÓÃnetdev_run_todoÀïÃæµÄº¯ÊıÀ´ÊÍ·ÅÏà¹Ø×ÊÔ´
static void net_set_todo(struct net_device *dev)
{
	list_add_tail(&dev->todo_list, &net_todo_list);
}

static void rollback_registered_many(struct list_head *head)
{
	struct net_device *dev, *tmp;

	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	list_for_each_entry_safe(dev, tmp, head, unreg_list) {
		/* Some devices call without registering
		 * for initialization unwind. Remove those
		 * devices and proceed with the remaining.
		 */
		if (dev->reg_state == NETREG_UNINITIALIZED) {
			pr_debug("unregister_netdevice: device %s/%p never "
				 "was registered\n", dev->name, dev);

			WARN_ON(1);
			list_del(&dev->unreg_list);
			continue;
		}

		BUG_ON(dev->reg_state != NETREG_REGISTERED);

		/* If device is running, close it first. */
		dev_close(dev);

		/* And unlink it from device chain. */
		unlist_netdevice(dev);

		dev->reg_state = NETREG_UNREGISTERING;
	}

	synchronize_net();

	list_for_each_entry(dev, head, unreg_list) {
		/* Shutdown queueing discipline. */
		dev_shutdown(dev);


		/* Notify protocols, that we are about to destroy
		   this device. They should clean all the things.
		*/
		call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

		if (!dev->rtnl_link_ops ||
		    dev->rtnl_link_state == RTNL_LINK_INITIALIZED)
			rtmsg_ifinfo(RTM_DELLINK, dev, ~0U);

		/*
		 *	Flush the unicast and multicast chains
		 */
		dev_uc_flush(dev);
		dev_mc_flush(dev);

		if (dev->netdev_ops->ndo_uninit)
			dev->netdev_ops->ndo_uninit(dev);

		/* Notifier chain MUST detach us from master device. */
		WARN_ON(dev->master);

		/* Remove entries from kobject tree */
		netdev_unregister_kobject(dev);
	}

	/* Process any work delayed until the end of the batch */
	dev = list_first_entry(head, struct net_device, unreg_list);
	call_netdevice_notifiers(NETDEV_UNREGISTER_BATCH, dev);

	synchronize_net();

	list_for_each_entry(dev, head, unreg_list)
		dev_put(dev);
}

static void rollback_reg111istered(struct net_device *dev)
{
	LIST_HEAD(single);

	list_add(&dev->unreg_list, &single);
	rollback_registered_many(&single);
}
//unregister_netdevice×îÖÕÒ²ÊÇµ÷ÓÃ¸Ãº¯Êı
static void rollback_registered(struct net_device *dev)
{
	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/* Some devices call without registering for initialization unwind. */
	/*
	  * Èç¹ûÉè±¸´¦ÓÚNETREG_UNINITIALIZED×´Ì¬£¬¼´Î´
	  * ³õÊ¼»¯×´Ì¬£¬ÔòÊä³öĞÅÏ¢ºó·µ»Ø¡£
	  */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		printk(KERN_DEBUG "unregister_netdevice: device %s/%p never "
				  "was registered\n", dev->name, dev);

		WARN_ON(1);
		return;
	}

	BUG_ON(dev->reg_state != NETREG_REGISTERED);

	/* If device is running, close it first. */
	/*
	  * Èç¹ûÉè±¸Ã»ÓĞ¹Ø±Õ£¬Ôòµ÷ÓÃ
	  * dev_close()½øĞĞ¹Ø±Õ
	  */
	dev_close(dev);

	/* And unlink it from device chain. */
	/*
	  * ½«´ı×¢ÏúµÄÍøÂçÉè±¸ÊµÀı´ÓÈ«¾Ö
	  * Á´±ídev_base¼°dev_name_head¡¢dev_index_head
	  * É¢ÁĞ±íÖĞÒÆ³ı¡£ÒÆ³ıºó²»ÄÜ×èÖ¹
	  * ÄÚºË×ÓÏµÍ³Ê¹ÓÃ¸ÃÉè±¸£¬ËûÃÇÈÔÈ»
	  * ÓµÓĞÖ¸Ïò¸Ãnet_device½á¹¹ÊµÀıµÄÖ¸Õë£¬
	  * Ö»ÓĞµ±ÒıÓÃ¼ÆÊıÎª0Ê±²Å»áÕæÕıÊÍ·Å
	  * ÊµÀı¡£
	  */
	unlist_netdevice(dev);

	/*
	  * ½«ÍøÂçÉè±¸ÊµÀıÉèÖÃÎªNETREG_UNREGISTERING
	  * ¼´Î´×¢²á×´Ì¬
	  */
	dev->reg_state = NETREG_UNREGISTERING;
	/*
	  * Í¬²½Êı¾İ°üµÄ½ÓÊÕ´¦Àí
	  */
	synchronize_net();

	/* Shutdown queueing discipline. */
	/*
	  * ÊÍ·ÅËùÓĞÓëÉè±¸Ïà¹ØµÄ¶ÓÁĞ¹æÔòÊµÀı
	  */
	dev_shutdown(dev);

	/* Notify protocols, that we are about to destroy
	   this device. They should clean all the things.
	*/
	/*
	  * ·¢ËÍNETDEV_UNREGISTERÏûÏ¢µ½netdev_chainÍ¨ÖªÁ´ÉÏ£¬
	  * ÒÔ±ãÍ¨Öª¶ÔÉè±¸×´Ì¬¸Ä±äÓĞĞËÈ¤µÄÆäËûÄÚºË
	  * ×é¼ş
	  */
	call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

	/*
	 *	Flush the unicast and multicast chains
	 */
	dev_unicast_flush(dev);
	/*
	  * ÊÍ·ÅÉèÖÃµ½ÍøÂçÉè±¸ÉÏµÄ×é²¥MACµØÖ·µÈĞÅÏ¢¡£
	  */
	dev_addr_discard(dev);

	/*
	  * ½øĞĞÇı¶¯³ÌĞòÏà¹ØµÄÏú»Ù²Ù×÷£¬Í¨³£
	  * ÊÇÏú»ÙÄÇĞ©ÔÚinitÖĞ³õÊ¼»¯µÄÊı¾İ
	  */
	if (dev->netdev_ops->ndo_uninit)
		dev->netdev_ops->ndo_uninit(dev);

	/* Notifier chain MUST detach us from master device. */
	WARN_ON(dev->master);

	/* Remove entries from kobject tree */
	netdev_unregister_kobject(dev);

	synchronize_net();

	dev_put(dev);
}

static void __netdev_init_queue_locks_one(struct net_device *dev,
					  struct netdev_queue *dev_queue,
					  void *_unused)
{
	spin_lock_init(&dev_queue->_xmit_lock);
	netdev_set_xmit_lockdep_class(&dev_queue->_xmit_lock, dev->type);
	dev_queue->xmit_lock_owner = -1;
}

static void netdev_init_queue_locks(struct net_device *dev)
{
	netdev_for_each_tx_queue(dev, __netdev_init_queue_locks_one, NULL);
	__netdev_init_queue_locks_one(dev, &dev->rx_queue, NULL);
}

unsigned long netdev_fix_features(unsigned long features, const char *name)
{
	/* Fix illegal SG+CSUM combinations. */
	if ((features & NETIF_F_SG) &&
	    !(features & NETIF_F_ALL_CSUM)) {
		if (name)
			printk(KERN_NOTICE "%s: Dropping NETIF_F_SG since no "
			       "checksum feature.\n", name);
		features &= ~NETIF_F_SG;
	}

	/* TSO requires that SG is present as well. */
	if ((features & NETIF_F_TSO) && !(features & NETIF_F_SG)) {//Ö»ÓĞNETIF_F_SGÓĞĞ§µÄÊ±ºò£¬TSO²Å»áÓĞĞ§
		if (name)
			printk(KERN_NOTICE "%s: Dropping NETIF_F_TSO since no "
			       "SG feature.\n", name);
		features &= ~NETIF_F_TSO;
	}

	if (features & NETIF_F_UFO) {
		if (!(features & NETIF_F_GEN_CSUM)) {
			if (name)
				printk(KERN_ERR "%s: Dropping NETIF_F_UFO "
				       "since no NETIF_F_HW_CSUM feature.\n",
				       name);
			features &= ~NETIF_F_UFO;
		}

		if (!(features & NETIF_F_SG)) {
			if (name)
				printk(KERN_ERR "%s: Dropping NETIF_F_UFO "
				       "since no NETIF_F_SG feature.\n", name);
			features &= ~NETIF_F_UFO;
		}
	}

	return features;
}
EXPORT_SYMBOL(netdev_fix_features);

/**
 *	netif_stacked_transfer_operstate -	transfer operstate
 *	@rootdev: the root or lower level device to transfer state from
 *	@dev: the device to transfer operstate to
 *
 *	Transfer operational state from root to device. This is normally
 *	called when a stacking relationship exists between the root
 *	device and the device(a leaf device).
 */
void netif_stacked_transfer_operstate(const struct net_device *rootdev,
					struct net_device *dev)
{
	if (rootdev->operstate == IF_OPER_DORMANT)
		netif_dormant_on(dev);
	else
		netif_dormant_off(dev);

	if (netif_carrier_ok(rootdev)) {
		if (!netif_carrier_ok(dev))
			netif_carrier_on(dev);
	} else {
		if (netif_carrier_ok(dev))
			netif_carrier_off(dev);
	}
}
EXPORT_SYMBOL(netif_stacked_transfer_operstate);

/**
 *	register_netdevice	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	Callers must hold the rtnl semaphore. You may want
 *	register_netdev() instead of this.
 *
 *	BUGS:
 *	The locking appears insufficient to guarantee two parallel registers
 *	will not get the same name.
 */
 /*
 * µ±´ı×¢²áµÄÍøÂçÉè±¸ÃûÈ·¶¨Ö®ºó£¬±ãµ÷ÓÃregister_netdevice()×¢²áÍøÂçÉè±¸£¬²¢½«
 * ÍøÂçÉè±¸ÃèÊö·û×¢²áµ½ÏµÍ³ÖĞ¡£Íê³É×¢²áºó£¬»á·¢ËÍNETDEV_REGISTERÏûÏ¢µ½netdev_chain
 * Í¨ÖªÁ´ÖĞ£¬Ê¹µÃËùÓĞ¶ÔÉè±¸×¢²á¸ĞĞËÈ¤µÄÄ£¿é¶¼ÄÜ½ÓÊÕÏûÏ¢¡£
 */
//ÍøÂçÉè±¸×¢²áµÄÊ±»ú:¼ÓÔØÍøÂçÉè±¸µÄÇı¶¯³ÌĞò ¡¢  ²ÁÈë¿ÉÈÈ²å°ÎµÄÍøÂçÉè±¸
//ÓÉÇı¶¯³ÌĞò¿ØÖÆµÄÍøÂçÉè±¸¶¼½«»á±»×¢²á  
////alloc_netdev·ÖÅäºÃ¿Õ¼äºó£¬µ÷ÓÃalloc_netdevÍê³É×¢²á
/*
  * ÔÚµ÷ÓÃ¸Ãº¯ÊıÇ°±ØĞëµ÷ÓÃrtnl_lock()À´»ñÈ¡rtnl»¥³âËø
  */
int register_netdevice(struct net_device *dev)
{
	struct hlist_head *head;
	struct hlist_node *p;
	int ret;
	struct net *net = dev_net(dev);

	/*
	  * Èç¹ûÎªÕæ£¬Ôò±íÊ¾Éè±¸²ãµÄ³õÊ¼»¯(net_dev_init())
	  * ÉĞÎ´Íê³É£¬´ËÊ±×¢²áÍøÂçÉè±¸¼´
	  * ÎªBUG¡£
	  */
	BUG_ON(dev_boot_phase);
	ASSERT_RTNL();

	/*
	  * 2.6°æ±¾ÄÚºËÖ§³ÖÄÚºËÇÀÕ¼£¬might_sleep()ºê¼ì²é
	  * ÊÇ·ñĞèÒªÖØĞÂµ÷¶È£¬Èç¹ûÊÇ£¬ÔòÖØĞÂµ÷¶È£¬
	  * ÎŞÂÛ´ËÊ±½ø³ÌÖ´ĞĞÔÚÄÚºË¿Õ¼ä»¹ÊÇ
	  * ÓÃ»§¿Õ¼ä¡£
	  */
	might_sleep();

	/* When net_device's are persistent, this will be fatal. */
	BUG_ON(dev->reg_state != NETREG_UNINITIALIZED);
	BUG_ON(!net);

	spin_lock_init(&dev->addr_list_lock);
	netdev_set_addr_lockdep_class(dev);
	netdev_init_queue_locks(dev);//¶Ô¶ÓÁĞÖĞµÄ·¢ËÍ¶ÓÁĞ_tx[]ËøºÍ½ÓÊÕ¶ÓÁĞrx_queue½øĞĞ³õÊ¼»¯

	dev->iflink = -1;

	/* Init, if this function is available */
       /* 
        * Èç¹ûÓĞ³õÊ¼»¯º¯Êı£¬ÔòÏÈ³õÊ¼»¯.
        * netdev_opsÓÉ²»Í¬µÄÍøÂçÉè±¸Çı¶¯³ÌĞò
        * À´³õÊ¼»¯£¬¿ÉÒÔ²Î¿¼3c501.cÖĞel1_probeº¯Êı
        * À´×¢²á3c501Íø¿¨µÄ¹ı³Ì
        */
	/*
	 * Èç¹ûÉè±¸Çı¶¯³ÌĞòÌá¹©ÁË³õÊ¼»¯º¯Êı£¬Ôò½øĞĞÏà¹Ø³õÊ¼»¯¡£
	 */
	if (dev->netdev_ops->ndo_init) {
		ret = dev->netdev_ops->ndo_init(dev);//Ò»°ãÔÚalloc_netdevµÄsetup»òÕßxxx_probe(ÀıÈçe100_probe)ÖĞ³õÊ¼»¯
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			goto out;
		}
	}

	/*
	 * µ÷ÓÃdev_valid_name()¼ì²â´ı×¢²áµÄÍøÂçÉè±¸ÃûÊÇ·ñÓĞĞ§¡£
	 */
	if (!dev_valid_name(dev->name)) {
		ret = -EINVAL;
		goto err_uninit;
	}
	/*
	 * µ÷ÓÃdev_new_index()ÎªÉè±¸·ÖÅäÒ»¸öÎ¨Ò»Ë÷ÒıºÅºÍÒ»¸öÓÃÓÚĞéÄâËíµÀÉè±¸
	 * µÄÎ¨Ò»±êÊ¶¡£Ë÷ÒıºÅÓÉÒ»¸ö32Î»¼ÆÊıÆ÷²úÉú£¬Ã¿µ±Ò»¸öĞÂÉè±¸¼Óµ½ÏµÍ³ÖĞ
	 * ¼ÆÊıÆ÷¾Í»áµİÔö¡£
	 */
	dev->ifindex = dev_new_index(net);
	if (dev->iflink == -1)
		dev->iflink = dev->ifindex; 

	/* Check for existence of name */
	/*
	 * ½«ÍøÂçÉè±¸Ìí¼Óµ½dev_name_headÉ¢ÁĞ±íÖĞ£¬²¢¼ì²âÊÇ·ñ´æÔÚÍ¬Ãû
	 * µÄÍøÂçÉè±¸¡£
	 */
	head = dev_name_hash(net, dev->name);
	hlist_for_each(p, head) {
		struct net_device *d
			= hlist_entry(p, struct net_device, name_hlist);
		if (!strncmp(d->name, dev->name, IFNAMSIZ)) {
			ret = -EEXIST;
			goto err_uninit;
		}
	}

	/* Fix illegal checksum combinations */
	/* 
        * ¼ì²éÌØĞÔ,ÕâĞ©ÌØĞÔµÄºê¶¨ÒåÔÚnet_device¶¨ÒåÊ±
        * ÒÔºêµÄĞÎÊ½ÁĞ³öÀ´£¬ÔÚinclude\linux\netdevice.h
        * NETIF_F_HW_CSUM: ¿ÉÒÔ¶ÔËùÓĞ°ü½øĞĞĞ£Ñé
        * NETIF_F_IP_CSUM: ¿ÉÒÔ¶ÔÊ¹ÓÃipv4Ğ­ÒéµÄTCP/UDP½øĞĞĞ£Ñé
        * NETIF_F_IPV6_CSUM: ¿ÉÒÔ¶ÔÊ¹ÓÃipv6Ğ­ÒéµÄTCP/UDP½øĞĞĞ£Ñé
        */
	if ((dev->features & NETIF_F_HW_CSUM) &&
	    (dev->features & (NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM))) {
		printk(KERN_NOTICE "%s: mixed HW and IP checksum settings.\n",
		       dev->name);
             /* 
              * Èç¹ûÉÏÊöÈı¸öÌØĞÔ¶¼ÉèÖÃ£¬Ôò½«NETIF_F_IP_CSUM¡¢NETIF_F_IPV6_CSUM
              * Á½¸öÌØĞÔÇå³ı¡£»òĞíÊÇÒòÎª¶ÔËùÓĞ°üÒÑ½øĞĞĞ£ÑéÁË£¬Õâ
              * Á½¸öÌØĞÔÒÑ¾­±»º­¸ÇÁË,»òĞí¸úºóÃæµÄÊµÏÖÓĞ¹Ø
              */
		dev->features &= ~(NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM);
	}

       /*
        * NETIF_F_NO_CSUM: ²»ÒªÇó¼ÆËãĞ£ÑéºÍ
        */
	if ((dev->features & NETIF_F_NO_CSUM) &&
	    (dev->features & (NETIF_F_HW_CSUM|NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM))) {
		printk(KERN_NOTICE "%s: mixed no checksumming and other settings.\n",
		       dev->name);
              /*½«ÏÂÁĞÈı¸öÌØĞÔÎ»Çå³ı */
		dev->features &= ~(NETIF_F_IP_CSUM|NETIF_F_IPV6_CSUM|NETIF_F_HW_CSUM);
	}

	dev->features = netdev_fix_features(dev->features, dev->name);

	/* Enable software GSO if SG is supported. */
	if (dev->features & NETIF_F_SG)
		dev->features |= NETIF_F_GSO;

       /* ³õÊ¼»¯devµÄdeviceÀàĞÍ³ÉÔ±dev*/
	netdev_initialize_kobject(dev);
       /* ÔÚsysfsÖĞ´´½¨¸úÉè±¸¹ØÁªµÄÏî*/
	ret = netdev_register_kobject(dev);
	if (ret)
		goto err_uninit;
	dev->reg_state = NETREG_REGISTERED;

	/*
	 *	Default initial state at registry is that the
	 *	device is present.
	 */

	set_bit(__LINK_STATE_PRESENT, &dev->state);

	dev_init_scheduler(dev);
	dev_hold(dev);
       /* ²åÈëµ½ÌØ¶¨ÃüÁî¿Õ¼äµÄÁ´±íºÍÉ¢ÁĞ±íÖĞ*/
	list_netdevice(dev);

	/* Notify protocols, that a new device appeared. */
	ret = call_netdevice_notifiers(NETDEV_REGISTER, dev);
	ret = notifier_to_errno(ret);
	if (ret) {
		rollback_registered(dev);
		dev->reg_state = NETREG_UNREGISTERED;
	}

out:
	return ret;

err_uninit:
	if (dev->netdev_ops->ndo_uninit)
		dev->netdev_ops->ndo_uninit(dev);
	goto out;
}

EXPORT_SYMBOL(register_netdevice);

/**
 *	init_dummy_netdev	- init a dummy network device for NAPI
 *	@dev: device to init
 *
 *	This takes a network device structure and initialize the minimum
 *	amount of fields so it can be used to schedule NAPI polls without
 *	registering a full blown interface. This is to be used by drivers
 *	that need to tie several hardware interfaces to a single NAPI
 *	poll scheduler due to HW limitations.
 */
int init_dummy_netdev(struct net_device *dev)
{
	/* Clear everything. Note we don't initialize spinlocks
	 * are they aren't supposed to be taken by any of the
	 * NAPI code and this dummy netdev is supposed to be
	 * only ever used for NAPI polls
	 */
	memset(dev, 0, sizeof(struct net_device));

	/* make sure we BUG if trying to hit standard
	 * register/unregister code path
	 */
	dev->reg_state = NETREG_DUMMY;

	/* initialize the ref count */
	atomic_set(&dev->refcnt, 1);

	/* NAPI wants this */
	INIT_LIST_HEAD(&dev->napi_list);

	/* a dummy interface is started by default */
	set_bit(__LINK_STATE_PRESENT, &dev->state);
	set_bit(__LINK_STATE_START, &dev->state);

	return 0;
}
EXPORT_SYMBOL_GPL(init_dummy_netdev);


/**
 *	register_netdev	- register a network device
 *	@dev: device to register
 *
 *	Take a completed network device structure and add it to the kernel
 *	interfaces. A %NETDEV_REGISTER message is sent to the netdev notifier
 *	chain. 0 is returned on success. A negative errno code is returned
 *	on a failure to set up the device, or if the name is a duplicate.
 *
 *	This is a wrapper around register_netdevice that takes the rtnl semaphore
 *	and expands the device name if you passed a format string to
 *	alloc_netdev.
 *///alloc_netdev·ÖÅäºÃ¿Õ¼äºó£¬µ÷ÓÃregister_netdevÍê³É×¢²á£¬Ğ¶ÔØµÄÊ±ºòunregister_netdeviceºÍfree_netdevÍê³É×¢Ïú²¢ÊÍ·ÅÄÚ´æ
int register_netdev(struct net_device *dev)
{
	int err;

	rtnl_lock();

	/*
	 * If the name is a format string the caller wants us to do a
	 * name allocation.
	 */
	if (strchr(dev->name, '%')) {
		err = dev_alloc_name(dev, dev->name);
		if (err < 0)
			goto out;
	}

	err = register_netdevice(dev);
out:
	rtnl_unlock();
	return err;
}
EXPORT_SYMBOL(register_netdev);

/*
 * netdev_wait_allrefs - wait until all references are gone.
 *
 * This is called when unregistering network devices.
 *
 * Any protocol or device that holds a reference should register
 * for netdevice notification, and cleanup and put back the
 * reference if they receive an UNREGISTER event.
 * We can get stuck here if buggy protocols don't correctly
 * call dev_put.
 */
/*
  * netdev_wait_allrefs()ÓÉÒ»¸öÑ­»·×é³É£¬Ö±µ½
  * ÍøÂçÉè±¸µÄÒıÓÃ¼ÆÊıÖµ¼õµ½0½áÊø¡£
  * µÈ´ı¹ı³ÌÖĞÃ¿Ãë·¢ËÍÒ»´ÎNETDEV_UNREGISTERÍ¨Öª£¬
  * Ã¿10sÔÚ¿ØÖÆÌ¨´òÓ¡Ò»´Î¾¯¸æ¡£ÔÚ·¢ËÍÍ¨ÖªÊ±£¬
  * Èç¹û·¢ÉúÁËÁ¬½Ó×´Ì¬¸Ä±äÊÂ¼ş£¬ÔòÒ»¶¨Òª´¦Àí¡£
  * ÈÎºÎ³ÖÓĞÍøÂçÉè±¸ÒıÓÃµÄĞ­Òé»òÉè±¸¶¼Òª×¢²á
  * ÍøÂçÉè±¸Í¨Öª£¬µ±ËüÃÇ½ÓÊÕµ½NETDEV_UNREGISTER
  * ÊÂ¼şÊ±£¬Òª¿ªÊ¼½øĞĞÇåÀí²¢ÊÍ·Å¶ÔÍøÂçÉè±¸µÄÒıÓÃ
  *///ÔÚunregister_netdevµÄÊ±ºò£¬×ßµ½ÕâÀï£¬Ã¿¹ı1sÏëÊ±¼äÍ¨ÖªÁ´ÉÏÃæÍ¨¸æÒ»´Î£¬ÆäËûÒıÓÃ¸ÃdevµÄÄ£¿éÊÕµ½¸ÃÍ¨Öªºó£¬ĞèÒªÊ¹ÓÃdev_putÀ´È¡Ïû¶Ô¸ÃdevµÄÒıÓÃ
static void netdev_wait_allrefs(struct net_device *dev)
{
	unsigned long rebroadcast_time, warning_time;

	rebroadcast_time = warning_time = jiffies;
	/*
	  * Ñ­»·µÈ´ı£¬Ö±µ½ÒıÓÃ¼ÆÊıÎª0
	  */
	while (atomic_read(&dev->refcnt) != 0) { //µÈÓÚ0µÄÊ±ºòÍË³öÑ­»·
		if (time_after(jiffies, rebroadcast_time + 1 * HZ)) {
			rtnl_lock();

			/* Rebroadcast unregister notification */
			/*
			  * ÔÚµÈ´ı¹ı³ÌÖĞÃ¿Ãë¹ã²¥Ò»´ÎNETDEV_UNREGISTER
			  * ÏûÏ¢¡£ÍøÂçÉè±¸ÔÚ×¢ÏúÆÚ¼ä£¬Èç¹û·¢ÉúÁË 
			  * Á¬½Ó×´Ì¬¸Ä±äÊÂ¼ş£¬ÔòÒ»¶¨Òª´¦Àí¡£
			  */
			call_netdevice_notifiers(NETDEV_UNREGISTER, dev);

			if (test_bit(__LINK_STATE_LINKWATCH_PENDING,
				     &dev->state)) {
				/* We must not have linkwatch events
				 * pending on unregister. If this
				 * happens, we simply run the queue
				 * unscheduled, resulting in a noop
				 * for this device.
				 */
				linkwatch_run_queue();
			}

			__rtnl_unlock();

			rebroadcast_time = jiffies;
		}

		msleep(250);

		/*
		  * ÔÚµÈ´ı¹ı³ÌÖĞ£¬Èç¹ûµÈ´ıÊ±¼ä³¬¹ı10s£¬
		  * Ôò»áÃ¿10s´òÓ¡Ò»´Î¾¯¸æĞÅÏ¢¡£
		  */
		if (time_after(jiffies, warning_time + 10 * HZ)) {
			printk(KERN_EMERG "unregister_netdevice: "
			       "waiting for %s to become free. Usage "
			       "count = %d\n",
			       dev->name, atomic_read(&dev->refcnt));
			warning_time = jiffies;
		}
	}
}

/* The sequence is:
 *
 *	rtnl_lock();
 *	...
 *	register_netdevice(x1);
 *	register_netdevice(x2);
 *	...
 *	unregister_netdevice(y1);
 *	unregister_netdevice(y2);
 *      ...
 *	rtnl_unlock();
 *	free_netdev(y1);
 *	free_netdev(y2);
 *
 * We are invoked by rtnl_unlock().
 * This allows us to deal with problems:
 * 1) We can delete sysfs objects which invoke hotplug
 *    without deadlocking with linkwatch via keventd.
 * 2) Since we run with the RTNL semaphore not held, we can sleep
 *    safely in order to wait for the netdev refcnt to drop to zero.
 *
 * We must not return until all unregister events added during
 * the interval the lock was held have been completed.
 */
/*
  * netdev_run_todo()º¯ÊıÓÃÀ´´¦Àí¶ÓÁĞnet_todo_listÉÏ
  * µÄÍøÂçÉè±¸£¬¼ÌĞø´¦ÀíÏà¹ØµÄ×¢ÏúÊÂÎñ¡£
  * Ö÷ÒªÊÇ×¢ÏúsysfsÖĞ¸ÃÉè±¸µÄ½áµã¡£×¢ÏúÊ±£¬
  * µÈ´ıÉè±¸µÄÒıÓÃ¼ÆÊıÎª0£¬ÔÙµ÷ÓÃÉè±¸
  * ×ÔÉíµÄdestruct()º¯Êı£¬Íê³É×¢Ïú¹ı³Ì¡£
  *///unregister_netdevµÄÊ±ºò°ÑdevÌí¼Óµ½ÁËnet_todo_listÁ´±íÖĞ£¬¼ûnet_set_todo
void netdev_run_todo(void)
{
	struct list_head list;

	/* Snapshot list, allow later requests */
	/*
	  * ÔÚ³ÖÓĞËøµÄ¹ı³ÌÖĞ£¬½«net_todo_list
	  * ÖĞµÄËùÓĞ¶ÔÏó¶¼´æ´¢µ½Ò»¸öÕ»ÉÏµÄ
	  * ÁÙÊ±±äÁ¿ÖĞ£¬ÕâÑù¾Í¿ÉÒÔÔÚÃ»ÓĞËø
	  * µÄÇé¿öÏÂ°²È«µØ´¦ÀíËùÓĞ´ıÏú»Ù
	  * µÄÉè±¸¡£ÕâÀïÕæÊÇ·Ç³£µÄÇÉÃî
	  */
	list_replace_init(&net_todo_list, &list);

	__rtnl_unlock();

	while (!list_empty(&list)) {
		struct net_device *dev
			= list_entry(list.next, struct net_device, todo_list);
		list_del(&dev->todo_list);

		if (unlikely(dev->reg_state != NETREG_UNREGISTERING)) {
			printk(KERN_ERR "network todo '%s' but state %d\n",
			       dev->name, dev->reg_state);
			dump_stack();
			continue;
		}

		dev->reg_state = NETREG_UNREGISTERED;

		/*
		  * Çå³ıÃ¿¸öCPU½ÓÊÕ¶ÓÁĞÉÏpendingµÄÊı¾İ°ü
		  */
		on_each_cpu(flush_backlog, dev, 1);

		/*
		  * µÈ´ıÖ±µ½´ı×¢ÏúµÄÍøÂçÉè±¸Ã»ÓĞÒıÓÃÎªÖ¹£¬
		  * Ò²¾ÍÊÇµÈ´ıÒıÓÃ¼ÆÊıÎª0.
		  */
		netdev_wait_allrefs(dev);

		/* paranoia */
		BUG_ON(atomic_read(&dev->refcnt));
		WARN_ON(dev->ip_ptr);
		WARN_ON(dev->ip6_ptr);
		WARN_ON(dev->dn_ptr);

		/*
		  * destructorº¯ÊıÍ¨³£»áµ÷ÓÃfree_netdev()º¯Êı£¬
		  * ÔÚ¸Ãº¯ÊıÖĞ»á¼ì²éÉè±¸µÄ×´Ì¬£¬
		  * Ö»ÓĞÔÚÉè±¸´¦ÓÚNETREG_UNINITIALIZED
		  * ×´Ì¬Ê±²Å»á½«devÕ¼ÓÃµÄÄÚ´æÊÍ·Å¡£
		  */
		if (dev->destructor)
			dev->destructor(dev);

		/* Free network device */
		/*
		  * ÔÚÕâ¸öº¯ÊıµÄºóĞøµ÷ÓÃ¹ı³ÌÖĞ
		  * »áµ÷ÓÃnetdev_release()º¯ÊıÀ´ÊÍ·Å
		  * devËùÕ¼ÓÃµÄÄÚ´æ¡£netdev_release()ÔÚ
		  * net_classÖĞµÄrelease³ÉÔ±ÖĞ£¬ÔÚ
		  * netdev_register_kobject()ÖĞÉèÖÃµ½device½á¹¹(¼´dev->dev)
		  * µÄclass³ÉÔ±ÖĞ¡£
		  */
		kobject_put(&dev->dev.kobj);
	}
}

/**
 *	dev_txq_stats_fold - fold tx_queues stats
 *	@dev: device to get statistics from
 *	@stats: struct net_device_stats to hold results
 */
void dev_txq_stats_fold(const struct net_device *dev,
			struct net_device_stats *stats)
{
	unsigned long tx_bytes = 0, tx_packets = 0, tx_dropped = 0;
	unsigned int i;
	struct netdev_queue *txq;

	for (i = 0; i < dev->num_tx_queues; i++) {
		txq = netdev_get_tx_queue(dev, i);
		tx_bytes   += txq->tx_bytes;
		tx_packets += txq->tx_packets;
		tx_dropped += txq->tx_dropped;
	}
	if (tx_bytes || tx_packets || tx_dropped) {
		stats->tx_bytes   = tx_bytes;
		stats->tx_packets = tx_packets;
		stats->tx_dropped = tx_dropped;
	}
}
EXPORT_SYMBOL(dev_txq_stats_fold);

/**
 *	dev_get_stats	- get network device statistics
 *	@dev: device to get statistics from
 *
 *	Get network statistics from device. The device driver may provide
 *	its own method by setting dev->netdev_ops->get_stats; otherwise
 *	the internal statistics structure is used.
 */
const struct net_device_stats *dev_get_stats(struct net_device *dev)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (ops->ndo_get_stats)
		return ops->ndo_get_stats(dev);

	dev_txq_stats_fold(dev, &dev->stats);
	return &dev->stats;
}
EXPORT_SYMBOL(dev_get_stats);

static void netdev_init_one_queue(struct net_device *dev,
				  struct netdev_queue *queue,
				  void *_unused)
{
	queue->dev = dev;
}

static void netdev_init_queues(struct net_device *dev)
{
	netdev_init_one_queue(dev, &dev->rx_queue, NULL);
	netdev_for_each_tx_queue(dev, netdev_init_one_queue, NULL);
	spin_lock_init(&dev->tx_global_lock);
}

/**
 *	alloc_netdev_mq - allocate network device
 *	@sizeof_priv:	size of private data to allocate space for
 *	@name:		device name format string
 *	@setup:		callback to initialize device
 *	@queue_count:	the number of subqueues to allocate
 *
 *	Allocates a struct net_device with private data area for driver use
 *	and performs basic initialization.  Also allocates subquue structs
 *	for each queue on the device at the end of the netdevice.
 */
 //sizeof_privÓÃÀ´´æ´¢Çı¶¯³ÌĞòË½ÓĞÊı¾İµÄ´óĞ¡£¬nameÉè±¸Ãû£¬setupÅäÖÃº¯ÊıÓÃÓÚ³õÊ¼»¯net_device½á¹¹ÊµÀıµÄ²¿·ÖÓò,Ò»°ãÓÃether_setupº¯Êı  queue_countÎª½ÓÊÕ¶ÓÁĞ¸öÊı
 //ÓÉalloc_netdev_mq·ÖÅäµÄ¿Õ¼ä×é³É£ºnet_deviceÊı¾İ½á¹¹µÄÄÚ´æ¿Õ¼ä+Ë½ÓĞÊı¾İÄÚ´æ¿Õ¼ä+Éè±¸·¢ËÍ¶ÓÁĞµÄÄÚ´æ¿Õ¼ä¡£
 //²»Í¬Éè±¸·ÖÅä²ÎÊı»á²»Ò»Ñù
struct net_device *alloc_n33etdev_mq(int sizeof_priv, const char *name,
		void (*setup)(struct net_device *), unsigned int queue_count)
{
	struct netdev_queue *tx;
	struct net_device *dev;
	size_t alloc_size;
	struct net_device *p;
#ifdef CONFIG_RPS
	struct netdev_rx_queue *rx;
	int i;
#endif

	BUG_ON(strlen(name) >= sizeof(dev->name));

	alloc_size = sizeof(struct net_device);
	if (sizeof_priv) {
		/* ensure 32-byte alignment of private area */
		alloc_size = ALIGN(alloc_size, NETDEV_ALIGN);
		alloc_size += sizeof_priv;
	}
	/* ensure 32-byte alignment of whole construct */
	alloc_size += NETDEV_ALIGN - 1;

	p = kzalloc(alloc_size, GFP_KERNEL);
	if (!p) {
		printk(KERN_ERR "alloc_netdev: Unable to allocate device.\n");
		return NULL;
	}

	tx = kcalloc(queue_count, sizeof(struct netdev_queue), GFP_KERNEL);
	if (!tx) {
		printk(KERN_ERR "alloc_netdev: Unable to allocate "
		       "tx qdiscs.\n");
		goto free_p;
	}

#ifdef CONFIG_RPS
	rx = kcalloc(queue_count, sizeof(struct netdev_rx_queue), GFP_KERNEL);
	if (!rx) {
		printk(KERN_ERR "alloc_netdev: Unable to allocate "
		       "rx queues.\n");
		goto free_tx;
	}

	atomic_set(&rx->count, queue_count);

	/*
	 * Set a pointer to first element in the array which holds the
	 * reference count.
	 */
	for (i = 0; i < queue_count; i++)
		rx[i].first = rx;
#endif

	dev = PTR_ALIGN(p, NETDEV_ALIGN);
	dev->padded = (char *)dev - (char *)p;

	if (dev_addr_init(dev))
		goto free_rx;

	dev_mc_init(dev);
	dev_uc_init(dev);

	dev_net_set(dev, &init_net);

	dev->_tx = tx;
	dev->num_tx_queues = queue_count;
	dev->real_num_tx_queues = queue_count;

#ifdef CONFIG_RPS
	dev->_rx = rx;
	dev->num_rx_queues = queue_count;
#endif

	dev->gso_max_size = GSO_MAX_SIZE;

	netdev_init_queues(dev);

	INIT_LIST_HEAD(&dev->ethtool_ntuple_list.list);
	dev->ethtool_ntuple_list.count = 0;
	INIT_LIST_HEAD(&dev->napi_list);
	INIT_LIST_HEAD(&dev->unreg_list);
	INIT_LIST_HEAD(&dev->link_watch_list);
	dev->priv_flags = IFF_XMIT_DST_RELEASE;
	setup(dev);
	strcpy(dev->name, name);
	return dev;

free_rx:
#ifdef CONFIG_RPS
	kfree(rx);
free_tx:
#endif
	kfree(tx);
free_p:
	kfree(p);
	return NULL;
}


/**
 *	alloc_netdev_mq - allocate network device
 *	@sizeof_priv:	size of private data to allocate space for
 *	@name:		device name format string
 *	@setup:		callback to initialize device
 *	@queue_count:	the number of subqueues to allocate
 *
 *	Allocates a struct net_device with private data area for driver use
 *	and performs basic initialization.  Also allocates subquue structs
 *	for each queue on the device at the end of the netdevice.
 */
/*
 * ÍøÂçÉè±¸ÓÉnet_device½á¹¹¶¨Òå,Ã¿¸önet_device½á¹¹ÊµÀı´ú±íÒ»¸öÍøÂçÉè±¸,¸Ã
 * ½á¹¹µÄÊµÀıÓÉalloc_netdev()·ÖÅä¿Õ¼ä,²ÎÊıËµÃ÷ÈçÏÂ:
 * @sizeof_priv:Ö¸¶¨ÓÃÓÚ´æ´¢Çı¶¯³ÌĞò²ÎÊıµÄË½ÓĞÊı¾İ¿é´óĞ¡,²Î¼ûalloc_etherdrv()º¯Êı.
 * @name:Éè±¸Ãû,Í¨³£ÊÇ¸öÇ°×º,ÏàÍ¬Ç°×ºµÄÉè±¸»á½øĞĞÍ³Ò»±àºÅ,ÒÔÈ·±£Éè±¸ÃûÎ¨Ò».
 * @setup:ÅäÖÃº¯Êı,ÓÃÓÚ³õÊ¼»¯net_device½á¹¹ÊµÀıµÄ²¿·ÖÓò,²Î¼ûether_setup()º¯Êı.
 */

/*
                    ±í8-1 alloc_netdev°ü¹üº¯Êı
ÍøÂçÉè±¸ÀàĞÍ            ·â×°º¯ÊıÃû
ÒÔÌ«Íø                   alloc_etherdev                     return alloc_netdev(sizeof_priv,"eth%d",ether_setup);   ÒÔÌ«ÍøÉè±¸È«²¿Ê¹ÓÃ¸Ãº¯Êı
¹âÏË·Ö²¼Ê½Êı¾İ½Ó¿Ú       alloc_fddidev                      return alloc_netdev(sizeof_priv,"fddi%d",fddi_setup);
¸ßĞÔÄÜ²¢ĞĞ½Ó¿Ú          alloc_hippi_dev                     return alloc_netdev(sizeof_priv,"hip%d",hippi_setup);
ÁîÅÆÍø                  alloc_trdev                         return alloc_netdev(sizeof_priv,"tr%d",tr_setup);
¹âÏËÍ¨µÀ                alloc_fcdev                         return alloc_netdev(sizeof_priv,"fc%d",fc_setup);
ºìÍâÊı¾İÁªÃË            alloc_irdadev                       return alloc_netdev(sizeof_priv,"irda%d",irda_device_setup);
*/
struct net_device *alloc_netdev_mq(int sizeof_priv, const char *name,
		void (*setup)(struct net_device *), unsigned int queue_count) //ÒÔe100Íø¿¨ÎªÀı£¬ÔÚe100_probeÖĞ½øĞĞµ÷ÓÃ
    //alloc_netdev·ÖÅäºÃ¿Õ¼äºó£¬µ÷ÓÃregister_netdevÍê³É×¢²á£¬Ğ¶ÔØµÄÊ±ºòunregister_netdeviceºÍfree_netdevÍê³É×¢Ïú²¢ÊÍ·ÅÄÚ´æ,ÕæÕı×¢ÏúÔÚnetdev_run_todo
{//ÔÚunregister_netdevµÄÊ±ºò£¬×ßµ½ÕâÀï£¬Ã¿¹ı1sÏëÊ±¼äÍ¨ÖªÁ´ÉÏÃæÍ¨¸æÒ»´Î£¬ÆäËûÒıÓÃ¸ÃdevµÄÄ£¿éÊÕµ½¸ÃÍ¨Öªºó£¬ĞèÒªÊ¹ÓÃdev_putÀ´È¡Ïû¶Ô¸ÃdevµÄÒıÓÃ¡£¼ûnetdev_wait_allrefs
	struct netdev_queue *tx;
	struct net_device *dev;
	size_t alloc_size;
	struct net_device *p;

	/*
	  * ¼ì²énameµÄ³¤¶ÈÊÇ·ñ³¬¹ı16¸ö×Ö½Ú
	  */
	BUG_ON(strlen(name) >= sizeof(dev->name));

	alloc_size = sizeof(struct net_device);
	if (sizeof_priv) {
		/* ensure 32-byte alignment of private area */
		alloc_size = ALIGN(alloc_size, NETDEV_ALIGN);
		alloc_size += sizeof_priv;
	}
	/* ensure 32-byte alignment of whole construct */
      /* 
       * ·ÖÅäµÄnet_deviceÊµÀı + Ë½ÓĞÊı¾İµÄÖ¸Õë»áÔİÊ±´æ´¢ÔÚÁÙÊ±±äÁ¿pÖĞ£¬
       * µ«ÊÇÕâ¸öµØÖ·ÓĞ¿ÉÄÜ²»ÊÇ32Î»¶ÔÆëµÄ£¬ËùÒÔÔÚºóÃæ
       * »áµ÷ÓÃPTR_ALIGN¶ÔÕâ¸öµØÖ·½øĞĞĞŞÕı¡£Èç¹ûp²»ÊÇ32Î»
       * ¶ÔÆëµÄ£¬¶ÔÆëºóµÄµØÖ·dev»áÔÚpÖ®ºó£¬ÕâÑùÔÚÇ°±ß
       * »áÁô³öÒ»¶Î¿ÕÏĞµÄµØÖ·¡£ËùÒÔÕâÀïÒª¼ÓÉÏ31£¬¶à
       * ·ÖÅäÒ»Ğ©ÄÚ´æ
       */
	alloc_size += NETDEV_ALIGN - 1;

	p = kzalloc(alloc_size, GFP_KERNEL);
	if (!p) {
		printk(KERN_ERR "alloc_netdev: Unable to allocate device.\n");
		return NULL;
	}

	/*
	  * ·ÖÅäÍøÂçÉè±¸µÄ·¢ËÍ¶ÓÁĞ
	  */ //¶à¸öqueue_count netdev_queue
	tx = kcalloc(queue_count, sizeof(struct netdev_queue), GFP_KERNEL);
	if (!tx) {
		printk(KERN_ERR "alloc_netdev: Unable to allocate "
		       "tx qdiscs.\n");
		goto free_p;
	}

	dev = PTR_ALIGN(p, NETDEV_ALIGN);
       /* ¼ÆËã·ÖÅäµÄµØÖ·ºÍÊµ¼ÊÊ¹ÓÃµÄµØÖ·Ö®Ç°µÄÆ«ÒÆ*/
	dev->padded = (char *)dev - (char *)p;

       /* ÔÚdev->dev_addrsÖĞÌí¼ÓÒ»Ïî£¬²¢ÇÒ³õÊ¼»¯dev_add*/
	if (dev_addr_init(dev))
		goto free_tx;

       /* ³õÊ¼»¯µ¥²¥µØÖ·*/
	//dev_unicast_init(dev);
    dev_mc_init(dev);
	dev_uc_init(dev);
       /* ÉèÖÃÉè±¸ËùÊôµÄÃüÃû¿Õ¼ä*/
	dev_net_set(dev, &init_net);

       /* ³õÊ¼»¯·¢ËÍ¶ÓÁĞ*/
	dev->_tx = tx; //_txµÄµÚ0¸öµØÖ·Îªdev->_tx[0], µÍN¸öÒ»´ÎÀàÍÆ
	dev->num_tx_queues = queue_count;
	dev->real_num_tx_queues = queue_count;

	dev->gso_max_size = GSO_MAX_SIZE;

	/*
	  * ³õÊ¼»¯Éè±¸µÄ·¢ËÍºÍ½ÓÊÕ¶ÓÁĞ
	  */
	netdev_init_queues(dev);

	INIT_LIST_HEAD(&dev->napi_list);
	dev->priv_flags = IFF_XMIT_DST_RELEASE;
     /* 
         * µ÷ÓÃsetupº¯ÊıÀ´³õÊ¼»¯Éè±¸£¬¶ÔÓÚÒÔÌ«
         * ÍøÉè±¸£¬Ä¬ÈÏº¯ÊıÊ½ether_setup()
         */
	setup(dev); //ÀıÈçppp_setup
	strcpy(dev->name, name); //name%dÖĞ%d¸³ÖµµÄµØ·½ÔÚregister_netdeviceÖĞµÄdev_get_valid_name
	return dev;

free_tx:
	kfree(tx);

free_p:
	kfree(p);
	return NULL;
}

EXPORT_SYMBOL(alloc_netdev_mq);

/**
 *	free_netdev - free network device
 *	@dev: device
 *
 *	This function does the last stage of destroying an allocated device
 * 	interface. The reference to the device object is released.
 *	If this is the last reference then it will be freed.
 *///alloc_netdev·ÖÅäºÃ¿Õ¼äºó£¬µ÷ÓÃregister_netdevÍê³É×¢²á£¬Ğ¶ÔØµÄÊ±ºòunregister_netdeviceºÍfree_netdevÍê³É×¢Ïú²¢ÊÍ·ÅÄÚ´æ
void free_netdev(struct net_device *dev)
{
	struct napi_struct *p, *n;

	release_net(dev_net(dev));

	kfree(dev->_tx);

	/* Flush device addresses */
	dev_addr_flush(dev);

	/* Clear ethtool n-tuple list */
	ethtool_ntuple_flush(dev);

	list_for_each_entry_safe(p, n, &dev->napi_list, dev_list)
		netif_napi_del(p);

	/*  Compatibility with error handling in drivers */
	if (dev->reg_state == NETREG_UNINITIALIZED) {
		kfree((char *)dev - dev->padded);
		return;
	}

	BUG_ON(dev->reg_state != NETREG_UNREGISTERED);
	dev->reg_state = NETREG_RELEASED;

	/* will free via device release */
	put_device(&dev->dev);
}
EXPORT_SYMBOL(free_netdev);

/**
 *	synchronize_net -  Synchronize with packet receive processing
 *
 *	Wait for packets currently being received to be done.
 *	Does not block later packets from starting.
 */
void synchronize_net(void)
{
	might_sleep();
	synchronize_rcu();
}
EXPORT_SYMBOL(synchronize_net);

/**
 *	unregister_netdevice_queue - remove device from the kernel
 *	@dev: device
 *	@head: list
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables.
 *	If head not NULL, device is queued to be unregistered later.
 *
 *	Callers must hold the rtnl semaphore.  You may want
 *	unregister_netdev() instead of this.
 */

void unregister_netdevice_queue(struct net_device *dev, struct list_head *head)
{
	ASSERT_RTNL();

	if (head) {
		list_move_tail(&dev->unreg_list, head);
	} else {
		rollback_registered(dev);
		/* Finish processing unregister after unlock */
		net_set_todo(dev);//×îÖÕÓÉnetdev_run_todoÍê³Énet_deviceÊÇ·ñ,free_netdev
	}
}
EXPORT_SYMBOL(unregister_netdevice_queue);

/**
 *	unregister_netdevice_many - unregister many devices
 *	@head: list of devices
 */
void unregister_netdevice_many(struct list_head *head)
{
	struct net_device *dev;

	if (!list_empty(head)) {
		rollback_registered_many(head);
		list_for_each_entry(dev, head, unreg_list)
			net_set_todo(dev);
	}
}
EXPORT_SYMBOL(unregister_netdevice_many);

/**
 *	unregister_netdev - remove device from the kernel
 *	@dev: device
 *
 *	This function shuts down a device interface and removes it
 *	from the kernel tables.
 *
 *	This is just a wrapper for unregister_netdevice that takes
 *	the rtnl semaphore.  In general you want to use this and not
 *	unregister_netdevice.
 */ //ÒÆ³ıdevÍø¿¨Éè±¸ÄÚºËÄ£¿éµÄÊ±ºò(Èçe100.ko)  »òÕß°ÎµôÈÈ²å°ÎÍø¿¨ ´¥·¢
 //×îÖÕÓÉnetdev_run_todoÍê³Énet_deviceÊÇ·ñ,free_netdev
 //ÔÚunregister_netdevµÄÊ±ºò£¬×ßµ½ÕâÀï£¬Ã¿¹ı1sÏëÊ±¼äÍ¨ÖªÁ´ÉÏÃæÍ¨¸æÒ»´Î£¬ÆäËûÒıÓÃ¸ÃdevµÄÄ£¿éÊÕµ½¸ÃÍ¨Öªºó£¬ĞèÒªÊ¹ÓÃdev_putÀ´È¡Ïû¶Ô¸ÃdevµÄÒıÓÃ¡£¼ûrtnl_unlock->netdev_wait_allrefs
void unregister_netdev(struct net_device *dev)
{
	rtnl_lock();
	unregister_netdevice(dev);
	rtnl_unlock();//µ÷ÓÃnetdev_run_todo
}
EXPORT_SYMBOL(unregister_netdev);

/**
 *	dev_change_net_namespace - move device to different nethost namespace
 *	@dev: device
 *	@net: network namespace
 *	@pat: If not NULL name pattern to try if the current device name
 *	      is already taken in the destination network namespace.
 *
 *	This function shuts down a device interface and moves it
 *	to a new network namespace. On success 0 is returned, on
 *	a failure a netagive errno code is returned.
 *
 *	Callers must hold the rtnl semaphore.
 */

int dev_change_net_namespace(struct net_device *dev, struct net *net, const char *pat)
{
	int err;

	ASSERT_RTNL();

	/* Don't allow namespace local devices to be moved. */
	err = -EINVAL;
	if (dev->features & NETIF_F_NETNS_LOCAL)
		goto out;

	/* Ensure the device has been registrered */
	err = -EINVAL;
	if (dev->reg_state != NETREG_REGISTERED)
		goto out;

	/* Get out if there is nothing todo */
	err = 0;
	if (net_eq(dev_net(dev), net))
		goto out;

	/* Pick the destination device name, and ensure
	 * we can use it in the destination network namespace.
	 */
	err = -EEXIST;
	if (__dev_get_by_name(net, dev->name)) {
		/* We get here if we can't use the current device name */
		if (!pat)
			goto out;
		if (dev_get_valid_name(dev, pat, 1))
			goto out;
	}

	/*
	 * And now a mini version of register_netdevice unregister_netdevice.
	 */

	/* If device is running close it first. */
	dev_close(dev);

	/* And unlink it from device chain */
	err = -ENODEV;
	unlist_netdevice(dev);

	synchronize_net();

	/* Shutdown queueing discipline. */
	dev_shutdown(dev);

	/* Notify protocols, that we are about to destroy
	   this device. They should clean all the things.
	*/
	call_netdevice_notifiers(NETDEV_UNREGISTER, dev);
	call_netdevice_notifiers(NETDEV_UNREGISTER_BATCH, dev);

	/*
	 *	Flush the unicast and multicast chains
	 */
	dev_uc_flush(dev);
	dev_mc_flush(dev);

	/* Actually switch the network namespace */
	dev_net_set(dev, net);

	/* If there is an ifindex conflict assign a new one */
	if (__dev_get_by_index(net, dev->ifindex)) {
		int iflink = (dev->iflink == dev->ifindex);
		dev->ifindex = dev_new_index(net);
		if (iflink)
			dev->iflink = dev->ifindex;
	}

	/* Fixup kobjects */
	err = device_rename(&dev->dev, dev->name);
	WARN_ON(err);

	/* Add the device back in the hashes */
	list_netdevice(dev);

	/* Notify protocols, that a new device appeared. */
	call_netdevice_notifiers(NETDEV_REGISTER, dev);

	/*
	 *	Prevent userspace races by waiting until the network
	 *	device is fully setup before sending notifications.
	 */
	rtmsg_ifinfo(RTM_NEWLINK, dev, ~0U);

	synchronize_net();
	err = 0;
out:
	return err;
}
EXPORT_SYMBOL_GPL(dev_change_net_namespace);

/*
  * Ã¿¸öCPU¶¼ÓĞ¸÷×ÔµÄsoftnet_data£¬Í¨³£Çé¿öÏÂ
  * CPU¶¼ÄÜ´¦Àísoftnet_dataÖĞµÄÊä³ö¶ÓÁĞºÍÊäÈë
  * ¶ÓÁĞµÈ¡£µ±CPU×´Ì¬±ä»¯Ê±£¬ÓĞÒ»¸ö×´Ì¬
  * ĞèÒªÌØÊâ´¦Àí£¬ÄÇ¾ÍÊÇCPU_DEAD£¬´ËÊ±
  * CPUÒÑÎŞ·¨¹¤×÷£¬Òò´ËĞèÒª½«¸ÃCPUµÄ
  * softnet_dataÊäÈëÊä³ö¶ÓÁĞÖĞµÄ±¨ÎÄ×ª½»¸ø
  * ÆäËûCPU´¦Àí¡£ÎªÁËÄÜÏìÓ¦CPU×´Ì¬µÄ±ä»¯£¬
  * ÔÚ½Ó¿Ú²ã³õÊ¼»¯º¯ÊıÖĞÍ¨¹ıhotcpu_notifier()×¢²á
  * ÁËÏìÓ¦CPU×´Ì¬±ä»¯µÄ»Øµ÷º¯Êıdev_cpu_callback()¡£
  * ²ÎÊıËµÃ÷ÈçÏÂ:
  * @nfb:°üÀ¨ÓÃÀ´ÏìÓ¦CPU×´Ì¬±ä»¯»Øµ÷º¯ÊıµÄĞÅÏ¢¿é¡£
  * @action:×´Ì¬·¢Éú±ä»¯µÄCPUµÄµ±Ç°×´Ì¬¡£
  */
static int dev_cpu_callback(struct notifier_block *nfb,
			    unsigned long action,
			    void *ocpu)
{
	struct sk_buff **list_skb;
	struct Qdisc **list_net;
	struct sk_buff *skb;
	unsigned int cpu, oldcpu = (unsigned long)ocpu;
	struct softnet_data *sd, *oldsd;

	/*
	  * Ö»´¦ÀíCPU_DEAD×´Ì¬»òCPU_DEAD_FROZENĞĞÎª£¬´¦ÓÚ¸Ã×´Ì¬
	  * µÄCPUÒÑ²»ÄÜÔÙ´¦ÀíÆäsoftnet_dataÉÏµÄÏà¹Ø¶ÓÁĞÁË£¬Òò´Ë
	  * ĞèÒª×÷ÏàÓ¦µÄ´¦Àí¡£
	  */
	if (action != CPU_DEAD && action != CPU_DEAD_FROZEN)
		return NOTIFY_OK;

	local_irq_disable();
	/*
	  * »ñÈ¡×´Ì¬·¢Éú±ä»¯CPUµÄsoftnet_dataÒÔ¼°µ±Ç°CPUµÄsoftnet_data¡£
	  */
	cpu = smp_processor_id();
	sd = &per_cpu(softnet_data, cpu);
	oldsd = &per_cpu(softnet_data, oldcpu);

	/* Find end of our completion_queue. */
	/*
	  * ½«×´Ì¬·¢Éú±ä»¯CPUµÄcompletion_queue¶ÓÁĞÖĞ
	  * µÄ±¨ÎÄ×ªÒÆµ½µ±Ç°CPUµÄcompletion_queue¶ÓÁĞ¡£
	  */
	list_skb = &sd->completion_queue;
	while (*list_skb)
		list_skb = &(*list_skb)->next;
	/* Append completion queue from offline CPU. */
	*list_skb = oldsd->completion_queue;
	oldsd->completion_queue = NULL;

	/* Find end of our output_queue. */
	/*
	  * ½«×´Ì¬·¢Éú±ä»¯CPUµÄoutput_queue¶ÓÁĞÖĞ
	  * µÄ±¨ÎÄ×ªÒÆµ½µ±Ç°CPUµÄoutput_queue¶ÓÁĞ¡£
	  */
	list_net = &sd->output_queue;
	while (*list_net)
		list_net = &(*list_net)->next_sched;
	/* Append output queue from offline CPU. */
	*list_net = oldsd->output_queue;
	oldsd->output_queue = NULL;

	/*
	  * ¾­¹ıÒÔÉÏ²Ù×÷£¬µ±Ç°CPUµÄsoftnet_dataÖĞ¿ÉÄÜ´æÔÚ
	  * Íê³ÉÊä³öºÍµÈ´ıÊä³öµÄ±¨ÎÄ£¬Òò´ËÔÙ´Î¼¤»î
	  * Êı¾İ°üÊä³öÈíÖĞ¶Ï£¬ÒÔ±ãÊÍ·ÅÍê³ÉÊä³öµÄ±¨ÎÄ£¬
	  * Êä³öµÈ´ı·¢ËÍµÄ±¨ÎÄ¡£
	  */
	raise_softirq_irqoff(NET_TX_SOFTIRQ);
	local_irq_enable();

	/* Process offline CPU's input_pkt_queue */
	/*
	  * ×îºó´¦Àí×´Ì¬·¢Éú±ä»¯CPUµÄinput_pkt_queue¶ÓÁĞ£¬
	  * ½«¶ÓÁĞÉÏµÄ±¨ÎÄÊäÈëµ½ÉÏ²ãĞ­Òé
	  */
	while ((skb = __skb_dequeue(&oldsd->input_pkt_queue)))
		netif_rx(skb);

	return NOTIFY_OK;
}


/**
 *	netdev_increment_features - increment feature set by one
 *	@all: current feature set
 *	@one: new feature set
 *	@mask: mask feature set
 *
 *	Computes a new feature set after adding a device with feature set
 *	@one to the master device with current feature set @all.  Will not
 *	enable anything that is off in @mask. Returns the new feature set.
 */
unsigned long netdev_increment_features(unsigned long all, unsigned long one,
					unsigned long mask)
{
	/* If device needs checksumming, downgrade to it. */
	if (all & NETIF_F_NO_CSUM && !(one & NETIF_F_NO_CSUM))
		all ^= NETIF_F_NO_CSUM | (one & NETIF_F_ALL_CSUM);
	else if (mask & NETIF_F_ALL_CSUM) {
		/* If one device supports v4/v6 checksumming, set for all. */
		if (one & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM) &&
		    !(all & NETIF_F_GEN_CSUM)) {
			all &= ~NETIF_F_ALL_CSUM;
			all |= one & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
		}

		/* If one device supports hw checksumming, set for all. */
		if (one & NETIF_F_GEN_CSUM && !(all & NETIF_F_GEN_CSUM)) {
			all &= ~NETIF_F_ALL_CSUM;
			all |= NETIF_F_HW_CSUM;
		}
	}

	one |= NETIF_F_ALL_CSUM;

	one |= all & NETIF_F_ONE_FOR_ALL;
	all &= one | NETIF_F_LLTX | NETIF_F_GSO | NETIF_F_UFO;
	all |= one & mask & NETIF_F_ONE_FOR_ALL;

	return all;
}
EXPORT_SYMBOL(netdev_increment_features);

static struct hlist_head *netdev_create_hash(void)
{
	int i;
	struct hlist_head *hash;

	hash = kmalloc(sizeof(*hash) * NETDEV_HASHENTRIES, GFP_KERNEL);
	if (hash != NULL)
		for (i = 0; i < NETDEV_HASHENTRIES; i++)
			INIT_HLIST_HEAD(&hash[i]);

	return hash;
}

/* Initialize per network namespace state */
static int __net_init netdev_init(struct net *net)
{
	INIT_LIST_HEAD(&net->dev_base_head);

	net->dev_name_head = netdev_create_hash();
	if (net->dev_name_head == NULL)
		goto err_name;

	net->dev_index_head = netdev_create_hash();
	if (net->dev_index_head == NULL)
		goto err_idx;

	return 0;

err_idx:
	kfree(net->dev_name_head);
err_name:
	return -ENOMEM;
}

/**
 *	netdev_drivername - network driver for the device
 *	@dev: network device
 *	@buffer: buffer for resulting name
 *	@len: size of buffer
 *
 *	Determine network driver for device.
 */
char *netdev_drivername(const struct net_device *dev, char *buffer, int len)
{
	const struct device_driver *driver;
	const struct device *parent;

	if (len <= 0 || !buffer)
		return buffer;
	buffer[0] = 0;

	parent = dev->dev.parent;

	if (!parent)
		return buffer;

	driver = parent->driver;
	if (driver && driver->name)
		strlcpy(buffer, driver->name, len);
	return buffer;
}

static void __net_exit netdev_exit(struct net *net)
{
	kfree(net->dev_name_head);
	kfree(net->dev_index_head);
}

static struct pernet_operations __net_initdata netdev_net_ops = {
	.init = netdev_init,
	.exit = netdev_exit,
};

static void __net_exit default_device_exit(struct net *net)
{
	struct net_device *dev, *aux;
	/*
	 * Push all migratable network devices back to the
	 * initial network namespace
	 */
	rtnl_lock();
	for_each_netdev_safe(net, dev, aux) {
		int err;
		char fb_name[IFNAMSIZ];

		/* Ignore unmoveable devices (i.e. loopback) */
		if (dev->features & NETIF_F_NETNS_LOCAL)
			continue;

		/* Leave virtual devices for the generic cleanup */
		if (dev->rtnl_link_ops)
			continue;

		/* Push remaing network devices to init_net */
		snprintf(fb_name, IFNAMSIZ, "dev%d", dev->ifindex);
		err = dev_change_net_namespace(dev, &init_net, fb_name);
		if (err) {
			printk(KERN_EMERG "%s: failed to move %s to init_net: %d\n",
				__func__, dev->name, err);
			BUG();
		}
	}
	rtnl_unlock();
}

static void __net_exit default_device_exit_batch(struct list_head *net_list)
{
	/* At exit all network devices most be removed from a network
	 * namespace.  Do this in the reverse order of registeration.
	 * Do this across as many network namespaces as possible to
	 * improve batching efficiency.
	 */
	struct net_device *dev;
	struct net *net;
	LIST_HEAD(dev_kill_list);

	rtnl_lock();
	list_for_each_entry(net, net_list, exit_list) {
		for_each_netdev_reverse(net, dev) {
			if (dev->rtnl_link_ops)
				dev->rtnl_link_ops->dellink(dev, &dev_kill_list);
			else
				unregister_netdevice_queue(dev, &dev_kill_list);
		}
	}
	unregister_netdevice_many(&dev_kill_list);
	rtnl_unlock();
}

static struct pernet_operations __net_initdata default_device_ops = {
	.exit = default_device_exit,
	.exit_batch = default_device_exit_batch,
};

/*
 *	Initialize the DEV module. At boot time this walks the device list and
 *	unhooks any devices that fail to initialise (normally hardware not
 *	present) and leaves us with a valid list of present and active devices.
 *
 */
/*
  * Éè±¸´¦Àí²ãµÄ³õÊ¼»¯º¯Êı.
  * ÔÚÏµÍ³Æô¶¯Ê±£¬net_dev_init()µÄ³õÊ¼»¯ÓÅÏÈ¼¶
  * ÊÇsubsys_initcall£¬ÓÃÀ´³õÊ¼»¯Ïà¹Ø
  * ½Ó¿Ú²ã£¬Èç×¢²á¼ÇÂ¼Ïà¹ØÍ³¼ÆĞÅÏ¢µÄproc
  * ÎÄ¼ş£¬³õÊ¼»¯Ã¿¸öCPUµÄsoftnet_data£¬×¢²áÍøÂç
  * ±¨ÎÄÊäÈë/Êä³öÈíÖĞ¶ÏÒÔ¼°´¦ÀíÀı³Ì£¬×¢²á
  * ÏìÓ¦CPU×´Ì¬±ä»¯µÄ»Øµ÷º¯ÊıµÈ¡£
  */
/*
 *       This is called single threaded during boot, so no need
 *       to take the rtnl semaphore.
 *///Éè±¸ÎïÀí²ãµÄ³õÊ¼»¯net_dev_init
 //TCP/IPĞ­ÒéÕ»³õÊ¼»¯inet_init  ÆäÊµ´«Êä²ãµÄĞ­Òé³õÊ¼»¯Ò²ÔÚÕâÀïÃæ
 //´«Êä²ã³õÊ¼»¯proto_init
 //Ì×½Ó¿Ú²ã³õÊ¼»¯sock_init   netfilter_initÔÚÌ×½Ó¿Ú²ã³õÊ¼»¯µÄÊ±ºòÒ²³õÊ¼»¯ÁË
static int __init net_dev_init(void)
{
	int i, rc = -ENOMEM;

	BUG_ON(!dev_boot_phase);

	if (dev_proc_init())//×¢²á/proc/net/devºÍ/proc/net/softnet_statÎÄ¼ş£¬Ö»¶ÁÎÄ¼ş£¬´æ·ÅÒ»Ğ©ÍøÂçÉè±¸×´Ì¬ºÍÍ³¼ÆĞÅÏ¢
		goto out;

	if (netdev_kobject_init()) //netdev_kobject_init»á´´½¨/sys/class/netÄ¿Â¼£¬ÔÚ´ËÄ¿Â¼ÏÂ£¬Ã¿¸öÒÑ×¢²áµÄÍøÂçÉè±¸¶¼»áÓĞÒ»¸ö×ÓÄ¿Â¼¡£ÀıÈçifconfigÀïÃæµÄeth0ĞÅÏ¢¶¼¿ÉÒÔÔÚÕâÀïÃæ²é¿´
        
		goto out;

    /*
	 * ³õÊ¼»¯ÍøÂç´¦Àíº¯ÊıÉ¢ÁĞ±íptype_base¡£ÕâĞ©´¦Àíº¯Êı
	 * ÓÃÀ´´¦Àí½ÓÊÕµ½µÄ²»Í¬Ğ­Òé×å±¨ÎÄ¡£
	 */
	INIT_LIST_HEAD(&ptype_all);
	for (i = 0; i < PTYPE_HASH_SIZE; i++)
		INIT_LIST_HEAD(&ptype_base[i]);//³õÊ¼»¯ÍøÂç´¦Àíº¯ÊıÉ¢ÁĞ±í£¬ÕâĞ©´¦Àíº¯ÊıÓÃÀ´´¦Àí½ÓÊÕµ½µÄ²»Í¬Ğ­Òé×åµÄ±¨ÎÄ

    /*
	  * ×¢²áÔÚnetÃüÃû¿Õ¼äµÄ³õÊ¼»¯ºÍÍË³ö²Ù×÷¡£
	  * netdev_net_opsÖĞ»á·Ö±ğ³õÊ¼»¯ÒÔÃû³ÆºÍË÷Òı
	  * Îª²éÕÒµÄÁ´±í
	  */
	if (register_pernet_subsys(&netdev_net_ops))
		goto out;

	/*
	 *	Initialise the packet receive queues.
	 */

    /*
	 * ³õÊ¼»¯ÓëCPUÏà¹ØµÄ½ÓÊÕ¶ÓÁĞ¡£
	 * update:³õÊ¼»¯Ã¿¸öCPUµÄsoftnet_data£¬°üÀ¨
	 * Íê³É·¢ËÍÊı¾İ°üµÄµÈ´ıÊÍ·Å¶ÓÁĞ£¬ÒÔ¼°
	 * ·ÇNAPIÇı¶¯µÄÊäÈë¶ÓÁĞ¡¢ÂÖÑ¯º¯Êı
	 */
	for_each_possible_cpu(i) {//³õÊ¼»¯ÓëCPU½ÓÊÕÏà¹ØµÄ¶ÓÁĞ
		struct softnet_data *sd = &per_cpu(softnet_data, i);

		memset(sd, 0, sizeof(*sd));
		skb_queue_head_init(&sd->input_pkt_queue);
		skb_queue_head_init(&sd->process_queue);
		sd->completion_queue = NULL;
		INIT_LIST_HEAD(&sd->poll_list);
		sd->output_queue = NULL;
		sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
		sd->csd.func = rps_trigger_softirq;
		sd->csd.info = sd;
		sd->csd.flags = 0;
		sd->cpu = i;
#endif

		sd->backlog.poll = process_backlog;
		sd->backlog.weight = weight_p;
		sd->backlog.gro_list = NULL;
		sd->backlog.gro_count = 0;
	}

	dev_boot_phase = 0;//±êÊ¶ÍøÂçÉè±¸³õÊ¼»¯ÒÑÍê³É

	/* The loopback device is special if any other network devices
	 * is present in a network namespace the loopback device must
	 * be present. Since we now dynamically allocate and free the
	 * loopback device ensure this invariant is maintained by
	 * keeping the loopback device as the first device on the
	 * list of network devices.  Ensuring the loopback devices
	 * is the first device that appears and the last network device
	 * that disappears.
	 */
	if (register_pernet_device(&loopback_net_ops)) //×¢²áÍøÂçÉè±¸"lo"£¬ifconfigÀïÃæµÄlo          ×¢²áÍøÂçÃüÁî¿Õ¼äÉè±¸£¬È·±£loopbackÉè±¸ÔÚËùÓĞÍøÂçÉè±¸ÖĞ×îÏÈ³öÏÖºÍ×îºóÏûÊ§ 
        
		goto out;

	if (register_pernet_device(&default_device_ops))
		goto out;

    /*
	 * ÔÚÈíÖĞ¶ÏÏµÍ³ÖĞ×¢²áÁ½¸öÈíÖĞ¶ÏNET_TX_SOFTIRQºÍ
	 * NET_RX_SOFTIRQ£¬ÓÃÓÚÍøÂçÊı¾İµÄ·¢ËÍºÍ½ÓÊÕ¡£ÒòÎª
	 * ÈíÖĞ¶ÏµÄĞÔÄÜ±È½ÏºÃ£¬¶øÍøÂçÊı¾İµÄ½ÓÊÕºÍ·¢ËÍ
	 * ¶ÔĞÔÄÜÒªÇó±È½Ï¸ß£¬Òò´Ë½«ÈíÖĞ¶Ï×÷ÎªÏÂ°ë²¿À´
	 * Ê¹ÓÃ¡£
	 * update:×¢²áÍøÂç±¨ÎÄÊäÈë/Êä³öÈíÖĞ¶Ï¼°Æä´¦ÀíÀı³Ì¡£
	 *///ÏÂ°ë²¿ºÍÉÏ°ë²¿×î´óµÄ²»Í¬ÊÇÏÂ°ë²¿ÊÇ¿ÉÖĞ¶ÏµÄ£¬¶øÉÏ°ë²¿ÊÇ²»¿ÉÖĞ¶ÏµÄ£¬ÏÂ°ë²¿¼¸ºõ×öÁËÖĞ¶Ï´¦Àí³ÌĞòËùÓĞµÄÊÂÇé£¬¶øÇÒ¿ÉÒÔ±»ĞÂµÄÖĞ¶Ï´ò¶Ï£¡ÏÂ°ë²¿ÔòÏà¶ÔÀ´Ëµ²¢²»ÊÇ·Ç³£½ô¼±µÄ£¬Í¨³£»¹ÊÇ±È½ÏºÄÊ±µÄ£¬Òò´ËÓÉÏµÍ³×ÔĞĞ°²ÅÅÔËĞĞÊ±»ú£¬²»ÔÚÖĞ¶Ï·şÎñÉÏÏÂÎÄÖĞÖ´ĞĞ¡£
	open_softirq(NET_TX_SOFTIRQ, net_tx_action);//×¢²áÁ½¸öÈíÖĞ¶Ï£¬ÓÃÓÚÍøÂçÊı¾İµÄ·¢ËÍºÍ½ÓÊÕ
	open_softirq(NET_RX_SOFTIRQ, net_rx_action);

    /*
	 * ÔÚÍ¨ÖªÁ´±íÉÏ×¢²áÒ»¸ö»Øµ÷º¯Êı£¬ÓÃÀ´ÏìÓ¦
	 * CPUÈÈ²å°ÎÊÂ¼ş¡£Ò»µ©½Óµ½Í¨Öª£¬CPUÊäÈë¶ÓÁĞ
	 * ÖĞµÄ°üÖğÒ»ÓÉnetif_rx()´¦Àí¡£
	 * update:×¢²áÏìÓ¦CPU×´Ì¬±ä»¯µÄ»Øµ÷º¯Êı¡£µ±CPU
	 * ×´Ì¬·¢Éú±ä»¯Ê±£¬»áµ÷ÓÃdev_cpu_callback()£¬À´´¦Àí
	 * ×´Ì¬·¢Éú±ä»¯µÄCPUµÄsoftnet_dataÖĞÏà¹Ø¶ÓÁĞ
	 */
	hotcpu_notifier(dev_cpu_callback, 0);//ÔÚÍ¨ÖªÁ´±íÉÏ×¢²áÒ»¸ö»Øµ÷º¯Êı£¬ÓÃÀ´ÏàÓ¦CPUÈÈ²å°ÎÊÂ¼ş£¬Ò»µ©½Óµ½Í¨Öª£¬CPUÊäÈë¶ÓÁĞÖĞµÄ°üÖğÒ»½»¸ønetif_rx´¦Àí

    /*
	 * ³õÊ¼»¯Ä¿µÄÂ·ÓÉ»º´æ
	 */
	dst_init();

    /*
	 * ³õÊ¼»¯ÍøÂçÉè±¸²ãµÄ×é²¥Ä£¿é£¬²¢ÔÚprocÎÄ¼şÏµÍ³ÖĞ
	 * Ôö¼ÓÎÄ¼ş/proc/net/dev_mcast,ÓÃÀ´´æ·ÅÄÚºËÖĞÍøÂçÉè±¸Óë
	 * IP×é²¥Ïà¹ØµÄ²ÎÊı¡£
	 */
	dev_mcast_init();
	rc = 0;
out:
	return rc;
}

subsys_initcall(net_dev_init);//Éè±¸ÎïÀí²ãµÄ³õÊ¼»¯

static int __init initialize_hashrnd(void)
{
	get_random_bytes(&hashrnd, sizeof(hashrnd));
	return 0;
}

late_initcall_sync(initialize_hashrnd);


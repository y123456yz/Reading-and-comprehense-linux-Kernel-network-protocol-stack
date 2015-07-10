#ifndef _GENLNET_SOCKET_H_
#define _GENLNET_SOCKET_H_

#include <linux/socket.h>
#include <linux/unistd.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>

/* XXX: redefine */
#define GENLNET_NAME          "genlnet name"
/* XXX: redefine */
#define GENLNET_VERSION       0x1
#define MAX_STR_LEN           100

enum {
    MSG_CMD_ATTR_UNSPEC = 0,
    MSG_CMD,
    __MSG_CMD_ATTR_MAX,
};

#define MSG_CMD_ATTR_MAX (__MSG_CMD_ATTR_MAX - 1)

/*
 * Commands sent from userspace
 * Not versioned. New commands should only be inserted at the enum's end
 * prior to __EFMP_MSG_CMD_MAX
 */
enum {
    MSG_CMD_UNSPEC = 0,    /* Reserved */
    MSG_CMD_SET,           /* user->kernel request/get-response */
    MSG_CMD_NOTIFY,        /* kernel->user event */
    __MSG_CMD_MAX,
};
#define MSG_CMD_MAX (__MSG_CMD_MAX - 1)

/* netlink 消息结构体 */
typedef struct genlnet_msg_s {
    struct nlmsghdr     n;
    struct genlmsghdr   g;
    char                data[100];
} genlnet_msg_t;

/*
 * Generic macros for dealing with netlink sockets. Might be duplicated
 * elsewhere. It is recommended that commercial grade applications use
 * libnl or libnetlink and use the interfaces provided by the library
 *
 * copy from Documentation/accounting/getdelays.c
 */
#undef  GENLMSG_DATA
#define GENLMSG_DATA(glh)       ((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))

#undef  GENLMSG_PAYLOAD
#define GENLMSG_PAYLOAD(glh)    (NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)

#undef  NLA_DATA
#define NLA_DATA(na)            ((void *)((char *)(na) + NLA_HDRLEN))

#undef  NLA_PAYLOAD
#define NLA_PAYLOAD(len)        (len - NLA_HDRLEN)

#endif /* _GENLNET_SOCKET_H_ */



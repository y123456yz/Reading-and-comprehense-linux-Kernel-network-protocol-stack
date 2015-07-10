#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/types.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "gnrl_nl_user.h"

int g_pid = 0;

/* general netlink family */
static struct genl_family genlnet_family = {
    .id = GENL_ID_GENERATE,                 /* 表示自动生成一个family id */
    .name = GENLNET_NAME,                   /* 名称 */
    .version = GENLNET_VERSION,             /* 版本号 */
    .maxattr = MSG_CMD_ATTR_MAX,            /* NLA TYPE MAX */
};

static int genlnet_msg_handle(struct sk_buff *skb, struct genl_info *info);

/* message operation */
static struct genl_ops genlnet_msg_trans_ops = {
    .cmd = MSG_CMD_SET,
    .doit = genlnet_msg_handle,
};

/* 从内核发消息给用户空间 */
/*
 * @pid:用户进行id
   @data:发送数据缓冲区
   @data_len:缓冲区长度
  */
static int genlnet_msg_send(int pid, char *data, uint32_t data_len)
{
    char buf[MAX_STR_LEN];
    void            *msg;
    int             ret;
    size_t          size;
    struct sk_buff  *skb;
    struct genlmsghdr   *genlhdr;
    void                *reply;

    memcpy(buf, data, data_len);
    size = nla_total_size(data_len) + nla_total_size(0);
    skb = genlmsg_new(size, GFP_KERNEL);
    if (skb == NULL) {
        printk("%s %d\n", __func__, __LINE__);
        return -1;
    }

    msg = genlmsg_put(skb, 0, 0, &genlnet_family, 0, MSG_CMD_NOTIFY);
    if (msg == NULL) {
        printk("%s %d\n", __func__, __LINE__);
        goto err;
    }

    ret = nla_put(skb, MSG_CMD, data_len, data);
    if (ret < 0) {
        printk("%s %d, ret = %d\n", __func__, __LINE__, ret);
        goto err;
    }

    genlhdr = nlmsg_data(nlmsg_hdr(skb));
    reply = genlmsg_data(genlhdr);

    ret = genlmsg_end(skb, reply);
    if (ret < 0) {
        printk("%s %d, ret = %d\n", __func__, __LINE__, ret);
        goto err;
    }

    ret = genlmsg_unicast(&init_net, skb, pid);
    if (ret < 0) {
        printk("%s %d, ret = %d\n", __func__, __LINE__, ret);
        goto err;
    }

    return 0;

err:
    //nlmsg_free(skb);
    return -1;
}

/* 用户空间发送数据过来，调用此接口进行处理 */
static int genlnet_msg_handle(struct sk_buff *skb, struct genl_info *info)
{
    char str[MAX_STR_LEN];
    void *data;
    uint32_t data_len;
    struct nlattr      *nla;
    
    nla = info->attrs[MSG_CMD];
    if (nla == NULL || nla_type(nla) != MSG_CMD) {
        printk("%s %d\n", __func__, __LINE__);
        return -1;
    }
    g_pid = info->snd_pid;

    data = nla_data(nla);
    data_len = nla_len(nla);
    memcpy(str, data, data_len);
    printk("%s\n", str);

    strcpy(str, "From kernel: hello user.");
    genlnet_msg_send(g_pid, str, strlen(str) + 1);

    return 0;
}

/* 创建一个netlink */
static int gnrl_register()
{
    int ret;
    
    ret = genl_register_family(&genlnet_family);
    if (ret < 0) {
        printk(KERN_ERR "%s %d: ret = %d\n", __func__, __LINE__, ret);
        return -1;
    }
    
    ret = genl_register_ops(&genlnet_family, &genlnet_msg_trans_ops);
    if (ret < 0) {
        printk(KERN_ERR "%s %d: ret = %d\n", __func__, __LINE__, ret);
        genl_unregister_family(&genlnet_family);
        return -1;
    }
   
    return 0;
}

/* 解除注册 */
static void gnrl_unregister()
{    
    if (genlnet_family.id != GENL_ID_GENERATE) {
        /* 这步可以省了 */
        genl_unregister_ops(&genlnet_family, &genlnet_msg_trans_ops);
        /* 必须 */
        genl_unregister_family(&genlnet_family);
    }
}

static int __init genlnet_init(void)
{
    if (gnrl_register() < 0) {
        return -1;
    }
    
    /* 创建内核线程：kthread_run */
    return 0;
}

static void __exit genlnet_exit(void)
{
    gnrl_unregister();
}

module_init(genlnet_init);
module_exit(genlnet_exit);
MODULE_LICENSE("GPL");


/* test_chain_0.c ：0. 申明一个通知链；1. 向内核注册通知链；2. 定义事件； 3. 导出符号，因而必需最后退出*/  
  
#include <linux/notifier.h>  
#include <linux/module.h>  
#include <linux/init.h>  
#include <linux/kernel.h> /* printk() */  
#include <linux/fs.h> /* everything() */  
  
#define TESTCHAIN_INIT 0x52U  
static RAW_NOTIFIER_HEAD(test_chain);  
  
/* define our own notifier_call_chain */  
static int call_test_notifiers(unsigned long val, void *v)  
{  
    return raw_notifier_call_chain(&test_chain, val, v);  
}  
EXPORT_SYMBOL(call_test_notifiers);  
  
/* define our own notifier_chain_register func */  
 static int register_test_notifier(struct notifier_block *nb)  
{  
    int err;  
    err = raw_notifier_chain_register(&test_chain, nb);  
  
    if(err)  
        goto out;  
  
out:  
    return err;  
}  
  
EXPORT_SYMBOL(register_test_notifier);  
  
static int __init test_chain_0_init(void)  
{  
    printk(KERN_DEBUG "I'm in test_chain_0\n");  
  
    return 0;  
}  
  
static void __exit test_chain_0_exit(void)  
{  
    printk(KERN_DEBUG "Goodbye to test_chain_0\n");  
//  call_test_notifiers(TESTCHAIN_EXIT, (int *)NULL);  
}  
  
MODULE_LICENSE("GPL v2");  
MODULE_AUTHOR("fishOnFly");  
  
module_init(test_chain_0_init);  
module_exit(test_chain_0_exit);  






  
/* test_chain_1.c ：1. 定义回调函数；2. 定义notifier_block；3. 向chain_0注册notifier_block；*/  
#include <linux/notifier.h>  
#include <linux/module.h>  
#include <linux/init.h>  
  
#include <linux/kernel.h> /* printk() */  
#include <linux/fs.h> /* everything() */  
  
extern int register_test_notifier(struct notifier_block *nb);  
#define TESTCHAIN_INIT 0x52U  
  
/* realize the notifier_call func */  
int test_init_event(struct notifier_block *nb, unsigned long event,  
    void *v)  
{  
    switch(event){  
    case TESTCHAIN_INIT:  
        printk(KERN_DEBUG "I got the chain event: test_chain_2 is on the way of init\n");  
        break;  
  
    default:  
        break;  
    }  
  
    return NOTIFY_DONE;  
}  
/* define a notifier_block */  
static struct notifier_block test_init_notifier = {  
    .notifier_call = test_init_event,  
};  
static int __init test_chain_1_init(void)  
{  
    printk(KERN_DEBUG "I'm in test_chain_1\n");  
    register_test_notifier(&test_init_notifier);//<span style="white-space:pre">  </span>// 由chain_0提供的设施  
    return 0;  
}  
  
static void __exit test_chain_1_exit(void)  
{  
    printk(KERN_DEBUG "Goodbye to test_clain_l\n");  
}  
  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("fishOnFly");  
  
module_init(test_chain_1_init);  
module_exit(test_chain_1_exit);  














  
/* test_chain_2.c：发出通知链事件*/  
  
#include <linux/notifier.h>  
#include <linux/module.h>  
#include <linux/init.h>  
#include <linux/kernel.h> /* printk() */  
#include <linux/fs.h> /* everything() */  
  
extern int call_test_notifiers(unsigned long val, void *v);  
#define TESTCHAIN_INIT 0x52U  
  
static int __init test_chain_2_init(void)  
{  
    printk(KERN_DEBUG "I'm in test_chain_2\n");  
    call_test_notifiers(TESTCHAIN_INIT, "no_use");  
      
    return 0;  
}  
  
static void __exit test_chain_2_exit(void)  
{  
    printk(KERN_DEBUG "Goodbye to test_chain_2\n");  
}  
  
MODULE_LICENSE("GPL v2");  
MODULE_AUTHOR("fishOnFly");  
  
module_init(test_chain_2_init);  
module_exit(test_chain_2_exit);  
  
/*
[wang2@iwooing: notifier_chian]$ sudo insmod./test_chain_0.ko  
[wang2@iwooing: notifier_chian]$ sudo insmod./test_chain_1.ko  
[wang2@iwooing: notifier_chian]$ sudo insmod./test_chain_2.ko  
   
  
[wang2@iwooing: notifier_chian]$ dmesg  
  
[ 5950.112649] I'm in test_chain_0  
[ 5956.766610] I'm in test_chain_1  
[ 5962.570003] I'm in test_chain_2  
[ 5962.570008] I got the chain event: test_chain_2 is on the way of init  
  
[ 6464.042975] Goodbye to test_chain_2  
[ 6466.368030] Goodbye to test_clain_l  
[ 6468.371479] Goodbye to test_chain_0 




# Makefile  
  
# Comment/uncomment the following line to disable/enable debugging  
# DEBUG = y  
  
  
# Add your debugging flag (or not) to CFLAGS  
ifeq ($(DEBUG),y)  
  DEBFLAGS = -O -g -DSCULL_DEBUG # "-O" is needed to expand inlines  
else  
  DEBFLAGS = -O2  
endif  
  
  
ifneq ($(KERNELRELEASE),)  
# call from kernel build system  
  
obj-m   := test_chain_0.o test_chain_1.o test_chain_2.o  
  
else  
  
KERNELDIR ?= /lib/modules/$(shell uname -r)/build  
PWD       := $(shell pwd)  
  
modules:  
    $(MAKE) -C $(KERNELDIR) M=$(PWD) modules  
  
endif  
  
  
  
clean:  
    rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions  
  
depend .depend dep:  
    $(CC) $(CFLAGS) -M *.c > .depend  
  
  
ifeq (.depend,$(wildcard .depend))  
include .depend  
endif  
*/

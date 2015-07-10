/*1)到4字节，同样可指定对齐到8字节。
struct student
{
    char name[7];
    uint32_t id;
    char subject[5];
} __attribute__ ((aligned(4))); 

2)不对齐，结构体的长度，就是各个变量长度的和
struct student
{
    char name[7];
    uint32_t id;
    char subject[5];
} __attribute__ ((packed));

/*  当用到typedef时，要特别注意__attribute__ ((packed))放置的位置，相当于：
  *  typedef struct str_stuct str;
  *  而struct str_struct 就是上面的那个结构。
  
typedef struct {
        __u8    a;
        __u8    b;
        __u8    c;
        __u16   d;
} __attribute__ ((packed)) str;
/* 在下面这个typedef结构中，__attribute__ ((packed))放在结构名str_temp之后，其作用是被忽略的，注意与结构str的区别。
typedef struct {
        __u8    a;
        __u8    b;
        __u8    c;
        __u16   d;
}str_temp __attribute__ ((packed));


TCP/IP协议栈相关参数设置方法:
QUOTE:
$ /proc/sys/net/core/wmem_max
最大socket写buffer,可参考的优化值:873200
$ /proc/sys/net/core/rmem_max
最大socket读buffer,可参考的优化值:873200
$ /proc/sys/net/ipv4/tcp_wmem
TCP写buffer,可参考的优化值: 8192 436600 873200
$ /proc/sys/net/ipv4/tcp_rmem
TCP读buffer,可参考的优化值: 32768 436600 873200
$ /proc/sys/net/ipv4/tcp_mem
同样有3个值,意思是:
net.ipv4.tcp_mem[0]:低于此值,TCP没有内存压力.
net.ipv4.tcp_mem[1]:在此值下,进入内存压力阶段.
net.ipv4.tcp_mem[2]:高于此值,TCP拒绝分配socket.
上述内存单位是页,而不是字节.可参考的优化值是:786432 1048576 1572864
$ /proc/sys/net/core/netdev_max_backlog
进入包的最大设备队列.默认是300,对重负载服务器而言,该值太低,可调整到1000.
$ /proc/sys/net/core/somaxconn
listen()的默认参数,挂起请求的最大数量.默认是128.对繁忙的服务器,增加该值有助于网络性能.可调整到256.
$ /proc/sys/net/core/optmem_max
socket buffer的最大初始化值,默认10K.
$ /proc/sys/net/ipv4/tcp_max_syn_backlog
进入SYN包的最大请求队列.默认1024.对重负载服务器,增加该值显然有好处.可调整到2048.
$ /proc/sys/net/ipv4/tcp_retries2
TCP失败重传次数,默认值15,意味着重传15次才彻底放弃.可减少到5,以尽早释放内核资源.
$ /proc/sys/net/ipv4/tcp_keepalive_time
$ /proc/sys/net/ipv4/tcp_keepalive_intvl
$ /proc/sys/net/ipv4/tcp_keepalive_probes
这3个参数与TCP KeepAlive有关.默认值是:
tcp_keepalive_time = 7200 seconds (2 hours)
tcp_keepalive_probes = 9
tcp_keepalive_intvl = 75 seconds
意思是如果某个TCP连接在idle 2个小时后,内核才发起probe.如果probe 9次(每次75秒)不成功,内核才彻底放弃,认为该连接已失效.对服务器而言,显然上述值太大. 可调整到:
/proc/sys/net/ipv4/tcp_keepalive_time 1800
/proc/sys/net/ipv4/tcp_keepalive_intvl 30
/proc/sys/net/ipv4/tcp_keepalive_probes 3
$ proc/sys/net/ipv4/ip_local_port_range
指定端口范围的一个配置,默认是32768 61000,已够大.

net.ipv4.tcp_syncookies = 1
表示开启SYN Cookies。当出现SYN等待队列溢出时，启用cookies来处理，可防范少量SYN攻击，默认为0，表示关闭；
net.ipv4.tcp_tw_reuse = 1
表示开启重用。允许将TIME-WAIT sockets重新用于新的TCP连接，默认为0，表示关闭；
net.ipv4.tcp_tw_recycle = 1
表示开启TCP连接中TIME-WAIT sockets的快速回收，默认为0，表示关闭。
net.ipv4.tcp_fin_timeout = 30
表示如果套接字由本端要求关闭，这个参数决定了它保持在FIN-WAIT-2状态的时间。
net.ipv4.tcp_keepalive_time = 1200
表示当keepalive起用的时候，TCP发送keepalive消息的频度。缺省是2小时，改为20分钟。
net.ipv4.ip_local_port_range = 1024 65000
表示用于向外连接的端口范围。缺省情况下很小：32768到61000，改为1024到65000。
net.ipv4.tcp_max_syn_backlog = 8192
表示SYN队列的长度，默认为1024，加大队列长度为8192，可以容纳更多等待连接的网络连接数。
net.ipv4.tcp_max_tw_buckets = 5000
表示系统同时保持TIME_WAIT套接字的最大数量，如果超过这个数字，TIME_WAIT套接字将立刻被清除并打印警告信息。默认为180000，改为 5000。对于Apache、Nginx等服务器，上几行的参数可以很好地减少TIME_WAIT套接字数量，但是对于Squid，效果却不大。此项参数可以控制TIME_WAIT套接字的最大数量，避免Squid服务器被大量的TIME_WAIT套接字拖死。

一般设置：
1 sudo vi /etc/sysctl.conf 
在最下面编辑添加： 
net.ipv4.tcp_fin_timeout = 30 
net.ipv4.tcp_keepalive_time = 1200 
net.ipv4.route.gc_timeout = 100 
net.ipv4.ip_local_port_range = 1024 65000 
net.ipv4.tcp_tw_reuse = 1 
net.ipv4.tcp_tw_recycle = 1 
net.ipv4.tcp_syn_retries = 1 
net.ipv4.tcp_synack_retries = 1 
net.ipv4.tcp_max_syn_backlog = 262144 
net.core.netdev_max_backlog = 262144 
net.core.somaxconn = 262144 
net.ipv4.tcp_mem = 94500000 915000000 927000000 
保存退出 
2 sudo /sbin/sysctl -p

静态链接库：当要使用时，连接器会找出程序所需的函数，然后将它们拷贝到执行文件，由于这种拷贝是完整的，所以一旦连接成功，静态程序库也就不再需要了。
动态库而言：某个程序在运行中要调用某个动态链接库函数的时候，操作系统首先会查看所有正在运行的程序，看在内存里是否已有此库函数的拷贝了。
如果有，则让其共享那一个拷贝;只有没有才链接载入。在程序运行的时候，被调用的动态链接库函数被安置在内存的某个地方，所有调用它的程序将指向这个代码段。
静态库占由于是直接拷贝完整代码的方式，说以占用空间会更大。

　动态库的搜索路径搜索的先后顺序是：   //*******注释：居然没有当前路径*********
　　1.编译目标代码时指定的动态库搜索路径;              //LDIRNAME
　　2.环境变量LD_LIBRARY_PATH指定的动态库搜索路径;
　　3.配置文件/etc/ld.so.conf中指定的动态库搜索路径;//只需在在该文件中追加一行库所在的完整路径如"/root/test/conf/lib"即可,然后ldconfig是修改生效。
　　4.默认的动态库搜索路径/lib;
　　5.默认的动态库搜索路径/usr/lib。



内核部分哪些需要调度，以及和应用层经常之间的调度过程，可以参考这里，一定要看，很重要:http://blog.csdn.net/allen6268198/article/details/7567679



linux下进行连接的缺省操作是首先连接动态库，也就是说，如果同时存在静态和动态库，不特别指定的话，将与动态库相连接。

file  readelf   objdump可以查看elf文件类型，大小端，32还是64位，运行环境等。
file 文件名              readelf -h 文件名。      objdump -d -j .text 文件名
readelf -d mcpd 查看mcpd依赖的.so库，在x86平台上也可以用ldd

root@darkstar:/var/yyz/ -mu/target/apps/mcp_2# file mcp_peer.o
mcp_peer.o: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
root@darkstar:/var/yyz/ -mu/target/apps/mcp_2# file *.so
libLdapRead.so: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, not stripped
root@darkstar:/var/yyz/ -mu/target/apps/mcp_2# file mcpd
mcpd: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), not stripped

objdump -d -j .text ./mcpd，查看mcpd进程的反汇编代码。
ldd查看进程需要的库文件。*.so文件  ldd - 打印共享库的依赖关系

其实big endian是指低地址存放最高有效字节(MSB),而little endian则是低地址存放最低有效字节(LSB)。

ELF文件包含三种类型:1) 可重定位的对象文件(Relocatable file),obj或者静态库     2) 可执行的对象文件(Executable file)，编译生成的可执行文件   3) 可被共享的对象文件(Shared object file)，动态库

mii-tool 命令可以查看接口是否link成功，还可以设置网卡的工作方式，是10M 1000M等， mii-tool -F 100baseTx-FD eth0 //将eth0改为100M,全双工工作模式


由此可见,我们可以将经常需要被读取的数据定义为 __read_mostly类型, 这样Linux内核被加载时,该数据将自动被存放到Cache中,以提高整个系统的执行效率.

wireshark使用过滤方法:tcp && ip.src == 192.168.0.1 && tcp.port==500 && !arp && udp.port >= 2048 && udp.length < 30 && ip.addr==1.2.2.2

struct socket结构中包含struct sock结构，在inet_create中，socket->ops被赋值为inetsw_array中的ops成员，socket->sock->sk_prot被赋值为inetsw_array中的prot成员

相关socket结构。struct socket里面的sk指针指向了struct sock。 
套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_connection_sock inet_connection_sock包含struct inet_sock，struct inet_sock包含struct sock 。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)

应用层socket函数会调用内核的__sock_create然后inet_create或者netlink_create
bind--->inet_bind或者netlink_bind  把本段端口和地址设置到inet_sock中，如果没有传本地端口进去，则分配一个本地端口
listen--->inet_listen  创建监听控制块，用于后面连接的时候保存信息。从新检查端口是否已经被使用。应用层最好设置SO_REUSEADDR，否则listn可能失败，因为关闭链路的过程需要一段时间，我们这里的端口可能还是前一个连接的端口。


好文章:由PPPOE看Linux网络协议栈的实现

容易混淆的一些网络知识:
TCP没有分片的概念，只有UDP有分片(由链路层MTU为界限，)，TCP是分段(由三次握手的MSS为界限,TCP层就是通过这个避免IP层的分片)。参考:http://blog.csdn.net/cumirror/article/details/5071234  总结：UDP不会分段，就由我IP来分。TCP会分段，当然也就不用我IP来分了！ 
http://zhidao.baidu.com/link?url=GhuO8cGJVKcqqdne6MozUvl1DcDUMMh6V4kvK2ja1nUugt5e2dOidoz_uhoUHozuPLljO3rDw_OCVP4HOVJypr6K2ATbFnxtxTVzSjBOsLG
基于seq ack TCP流的理解可以参考:http://blog.chinaunix.net/uid-25513153-id-187780.html


TCP层会缓存应用程序下发的数据包，用于重传等，UDP没有缓存，直接到IP层，所以UDP没有重传等机制。



TCP三次握手过程抓包分析:
原文地址：TCP三次握手协议 作者：futter521
  现在，我们来看一个完整的流程，在一个TCP socket上系统调用connect究竟是如何建立起一个到对端的连接的。我们还是以实验环境172.16.48.2向172.16.48.1的端口5002发起连接请求为例。
    第一步，172.16.48.2向172.16.48.1发起连接请求，发送一个SYN段，指明目的端口5002，通告自己的初始序号（ISN，由协议栈 随机产生的一个32位数），设置确认序号为0(因为还没有收到过对端的数据)，通告自己的滑动窗口大小为5840(对端是5792，这似乎有问题，有待进 一步细查)，窗口扩大因子为2(在首部选项中)，通告最大报文段长度为1460(本地局域网)，下面是数据内容(已剥去链路层的以太网首部和网络层的IP 首部)：
        数据内容                            含义
基本首部
        80 0e                               源端口(32782)
        13 8a                               目的端口(5002)
        00 00 07 bc                         初始序号ISN
        00 00 00 00                         确认序号
        a                                   首部长度
        0 02                                标志位，SYN=1
        16 d0                               滑动窗口大小(5840)
        64 9e                               校验和
        00 00                               紧急指针
TCP选项
        02 04 05 b4                         最大报文段长度(1460)
        04 02                               允许SACK
        08 0a 00 0a 79 14 00 00 00 00       时间戳(0x000a7914)，回显时间戳(0)
        01                                  占位。
        03 03 02                            窗口扩大因子(2)
    第二步，172.16.48.1收到请求包，检查标志位，发现SYN=1，认为这是一个初始化连接的请求，回应这个SYN，同时也发送自己的SYN段(即 ACK,SYN同时置位)。因为SYN本身要占用一个序号（还有标志FIN也要占用一个序号）。所以，确认序号设置为172.16.48.2的ISN加 1(即172.16.48.1期望收到来自172.16.48.2的下一个包的第一个序号为0x07bd。同时也要通告自己的初始序号，滑动窗口大小，窗 口扩大因子，最大报文段长度等，下面是数据内容：
        数据内容                            含义
基本TCP首部
        13 8a                               源端口(5002)
        80 0e                               目的端口(32782)
        98 8e 40 91                         初始序号ISN
        00 00 07 bd                         确认序号(对端ISN+1)
        a                                   首部长度
        0 12                                标志位，ACK=1, SYN=1
        16 a0                               滑动窗口大小
        65 d7                               校验和
        00 00                               紧急指针
TCP选项
        02 04 05 b4                         最大报文段长度(1460)
        04 02                               允许SACK
        08 0a 00 3c 25 8a 00 0a 79 14       时间戳(0x003c258a)，回显时间戳(000a7914)
        01                                  占位
        03 03 02                            窗口扩大因子(2)
    第三步，172.16.48.2对来自172.16.48.1的SYN段进行确认，至此，TCP三次握手协议完成，连接建立，在172.16.48.2收 到SYN段时，将自己对应的socket的状态由TCP_SYN_SENT改为TCP_ESTABLISHED，进入连接建立状态，下面是数据内容：
        数据内容                            含义
        80 0e                               源端口(32782)
        13 8a                               目的端口(5002)
        00 00 07 bd                         序号(已不是ISN了)
        98 8e 40 92                         确认序号（对端ISN+1)
        8                                   首部长度(8*4=32,有12字节的选项)
        0 10                                标志，ACK=1
        05 b4                               滑动窗口大小(1460，有问题？待确认)
        a5 8a                               校验和
        00 00                               紧急指针

        01                                  占位
        01                                  占位
        08 0a 00 0a 79 14 00 3c 25 8a       时间戳(0x0a007914), 回显时间戳(0x003c258a)


TCP基于流的SEQ ACK交互过程理解:
握手阶段：
序号 方向 seq ack
1　　A->B 10000 0
2 B->A 20000 10000+1=10001
3 A->B 10001 20000+1=20001
解释：
1：A向B发起连接请求，以一个随机数初始化A的seq,这里假设为10000，此时ACK＝0(表示还没有设定对端任何数据)
2：B收到A的连接请求后，也以一个随机数初始化B的seq，这里假设为20000，意思是：你的请求我已收到，我这方的数据流就从这个数开始。B的ACK是A的seq加1，即10000＋1＝10001
3：A收到B的回复后，它的seq是它的上个请求的seq加1，即10000＋1＝10001，意思也是：你的回复我收到了，我这方的数据流就从这个数开始。A此时的ACK是B的seq加1，即20000+1=20001
数据传输阶段：
序号　　方向　　　　　　seq ack size
23 A->B 40000 70000 1514
24 B->A 70000 40000+1514-54=41460 54
25 A->B 41460 70000+54-54=70000 1514
26 B->A 70000 41460+1514-54=42920 54
解释：
23:B接收到A发来的seq=40000,ack=70000,size=1514的数据包
24:于是B向A也发一个数据包，告诉B，你的上个包我收到了。B的seq就以它收到的数据包的ACK填充，ACK是它收到的数据包的SEQ加上数据包的大小(不包括以太网协议头，IP头，TCP头)，以证实B发过来的数据全收到了。
25:A在收到B发过来的ack为41460的数据包时，一看到41460，正好是它的上个数据包的seq加上包的大小，就明白，上次发送的数据包已安全到达。于是它再发一个数据包给B。这个正在发送的数据包的seq也以它收到的数据包的ACK填充，ACK就以它收到的数据包的seq(70000)加上包的size(54)填充,即ack=70000+54-54(全是头长，没数据项)。
其实在握手和结束时确认号应该是对方序列号加1,传输数据时则是对方序列号加上对方携带应用层数据的长度.如果从以太网包返回来计算所加的长度,就嫌走弯路了.
另外,如果对方没有数据过来,则自己的确认号不变,序列号为上次的序列号加上本次应用层数据发送长度.


http://www.cnblogs.com/bizhu/archive/2012/09/26/2704776.html  TCO


http://book.2cto.com/201306/25407.html
TCP头部的最后一个选项字段（options）是可变长的可选信息。这部分最多包含40字节，因为TCP头部最长是60字节（其中还包含前面讨论的20字节的固定部分）。典型的TCP头部选项结构如图3-4所示。
选项的第一个字段kind说明选项的类型。有的TCP选项没有后面两个字段，仅包含1字节的kind字段。第二个字段length（如果有的话）指定该选项的总长度，该长度包括kind字段和length字段占据的2字节。第三个字段info（如果有的话）是选项的具体信息。常见的TCP选项有7种，如图3-5所示。
kind=0是选项表结束选项。
kind=1是空操作（nop）选项，没有特殊含义，一般用于将TCP选项的总长度填充为4字节的整数倍。
kind=2是最大报文段长度选项。TCP连接初始化时，通信双方使用该选项来协商最大报文段长度（Max Segment Size，MSS）。TCP模块通常将MSS设置为（MTU-40）字节（减掉的这40字节包括20字节的TCP头部和20字节的IP头部）。这样携带TCP报文段的IP数据报的长度就不会超过MTU（假设TCP头部和IP头部都不包含选项字段，并且这也是一般情况），从而避免本机发生IP分片。对以太网而言，MSS值是1460（1500-40）字节。
kind=3是窗口扩大因子选项。TCP连接初始化时，通信双方使用该选项来协商接收通告窗口的扩大因子。在TCP的头部中，接收通告窗口大小是用16位表示的，故最大为65535字节，但实际上TCP模块允许的接收通告窗口大小远不止这个数（为了提高TCP通信的吞吐量）。窗口扩大因子解决了这个问题。假设TCP头部中的接收通告窗口大小是N，窗口扩大因子（移位数）是M，那么TCP报文段的实际接收通告窗口大小是N乘2M，或者说N左移M位。注意，M的取值范围是0～14。我们可以通过修改/proc/sys/net/ipv4/tcp_window_scaling内核变量来启用或关闭窗口扩大因子选项。
和MSS选项一样，窗口扩大因子选项只能出现在同步报文段中，否则将被忽略。但同步报文段本身不执行窗口扩大操作，即同步报文段头部的接收通告窗口大小就是该TCP报文段的实际接收通告窗口大小。当连接建立好之后，每个数据传输方向的窗口扩大因子就固定不变了。关于窗口扩大因子选项的细节，可参考标准文档RFC 1323。
kind=4是选择性确认（Selective Acknowledgment，SACK）选项。TCP通信时，如果某个TCP报文段丢失，则TCP模块会重传最后被确认的TCP报文段后续的所有报文段，这样原先已经正确传输的TCP报文段也可能重复发送，从而降低了TCP性能。SACK技术正是为改善这种情况而产生的，它使TCP模块只重新发送丢失的TCP报文段，不用发送所有未被确认的TCP报文段。选择性确认选项用在连接初始化时，表示是否支持SACK技术。我们可以通过修改/proc/sys/net/ipv4/tcp_sack内核变量来启用或关闭选择性确认选项。
kind=5是SACK实际工作的选项。该选项的参数告诉发送方本端已经收到并缓存的不连续的数据块，从而让发送端可以据此检查并重发丢失的数据块。每个块边沿（edge of block）参数包含一个4字节的序号。其中块左边沿表示不连续块的第一个数据的序号，而块右边沿则表示不连续块的最后一个数据的序号的下一个序号。这样一对参数（块左边沿和块右边沿）之间的数据是没有收到的。因为一个块信息占用8字节，所以TCP头部选项中实际上最多可以包含4个这样的不连续数据块（考虑选项类型和长度占用的2字节）。
kind=8是时间戳选项。该选项提供了较为准确的计算通信双方之间的回路时间（Round Trip Time，RTT）的方法，从而为TCP流量控制提供重要信息。我们可以通过修改/proc/sys/net/ipv4/tcp_timestamps内核变量来启用或关闭时间戳选项。



SACK选择确认选项 
1.前言 
TCP通信时，如果发送序列中间某个数据包丢失，TCP会通过重传最后确认的包开始的后续包，这样原先已经正确传输的包也可能重复发送，急剧降低了TCP性能。为改善这种情况，发展出SACK(Selective Acknowledgment, 选择性确认)技术，使TCP只重新发送丢失的包，不用发送后续所有的包，而且提供相应机制使接收方能告诉发送方哪些数据丢失，哪些数据重发了，哪些数 据已经提前收到等。 
2.选项格式 
SACK信息是通过TCP头的选项部分提供的，信息分两种，一种标识是否支持SACK，是在TCP握手时发送；另一种是具体的SACK信息。 
SACK允许选项 
       +---------+--------------+ 
       | Kind=4   | Length=2     | 
       +---------+-------------+ 
该选项只允许在有SYN标志的TCP包中，也即TCP握手的前两个包中，分别表示各自是否支持SACK。 
SACK选项 
选项长度: 可变，但整个TCP选项长度不超过40字节，实际最多不超过4组边界值。
                         +--------+--------+
                         | Kind=5 | Length | 
       +--------+--------+--------+-----------------+ 
       |       Left Edge of 1st Block                 | 
       +--------+--------+--------+-----------------+ 
       |       Right Edge of 1st Block               | 
       +--------+--------+--------+-----------------+ 
       |                                             | 
       /       。。。       . . .   。。。。。         / 
       |                                             | 
       +--------+--------+--------+-----------------+ 
       |       Left Edge of nth Block                 | 
       +--------+--------+--------+----------------+ 
       |       Right Edge of nth Block               | 
       +--------+--------+--------+----------------+ 
该选项参数告诉对方已经接收到并缓存的不连续的数据块，注意都是已经接收的，发送方可根据此信息检查究竟是哪个块丢失，从而发送相应的数据块。 
* Left Edge of Block 
不连续块的第一个数据的序列号。 
* Right Edge of Block 
不连续块的最后一个数据的序列号之后的序列号。表示(Left Edge - 1)和(Right Edge)处序列号的数据没能接收到。 
3.工作过程 
SACK的产生 
SACK通常都是由TCP接收方产生的，在TCP握手时如果接收到对方的SACK允许选项同时自己也支持SACK的话，在接收异常时就可以发送SACK包通知发送方。 

对中间有丢包或延迟时的SACK 
如果TCP接收方接收到非期待序列号的数据块时，如果该块的序列号小于期待的序列号，说明是网络复制或重发的包，可以丢弃；如果收到的数据块序列号大于期待的序列号，说明中间包被丢弃或延迟，此时可以发送SACK通知发送方出现了网络丢包。 
为反映接收方的接收缓存和网络传输情况，SACK中的第一个块必须描述是那个数据块激发此SACK选项的，接收方应该尽可能地在SACK选项部分中填写尽可能多的块信息，即使空间有限不能全部写完，SACK选项中要报告最近接收的不连续数据块，让发送方能了解当前网络传输情况的最新信息。 
对重发包的SACK(D-SACK) 
RFC2883中对SACK进行了扩展，在SACK中描述的是收到的数据段，这些数据段可以是正常的，也可能是重复发送的，SACK字段具有描述重复发送的数据段的能力，在第一块SACK数据中描述重复接收的不连续数据块的序列号参数，其他SACK数据则描述其他正常接收到的不连续数据，因此第一块SACK描述的序列号会比后面的SACK描述的序列号大；而在接收到不完整的数据段的情况下，SACK范围甚至可能小于当前的ACK值。通过这种方法，发送方可以更仔细判断出当前网络的传输情况，可以发现数据段被网络复制、错误重传、ACK丢失引起的重传、重传超时等异常的网络状况。 


发送方对SACK的响应 
TCP发送方都应该维护一个未确认的重发送数据队列，数据未被确认前是不能释放的，这个从重发送队列中的每个数据块都有一个标志位“SACKed”标识是否该块被SACK过，对于已经被SACK过的块，在重新发送数据时将被跳过。发送方接收到接收方SACK信息后，根据SACK中数据标志重发送队列中相应的数据块的“SACKed”标志，但如果接收不到接收方数据，超时后，所有重发送队列中数据块的SACKed位都要清除，因为可能接收方已经出现了异常。 
4.应用举例 
发送方发送的数据   接收方接收的数据(包括SACK)   接收方发送的ACK 


SACK累加接收的数据 
         5000-5499       (该包丢失)
         5500-5999       5500-5999     5000, SACK=5500-6000 
         6000-6499       6000-6499     5000, SACK=5500-6500 
         6500-6999       6500-6999     5000, SACK=5500-7000 
         7000-7499       7000-7499     5000, SACK=5500-7500 
数据包丢失，ACK丢失 
         3000-3499       3000-3499     3500 (ACK包丢失)
         3500-3999       3500-3999     4000 (ACK包丢失) 
         4000-4499       (该包丢失) 
         4500-4999       4500-4999     4000, SACK=4500-5000 (ACK包丢失) 
         3000-3499       3000-3499     4000, SACK=3000-3500, 4500-5000 
                                               ---------此为D-SACK 
数据段丢失和延迟 
         500-999         500-999       1000
         1000-1499       (延迟) 
         1500-1999       (该包丢失) 
         2000-2499       2000-2499     1000, SACK=2000-2500 
         1000-2000       1000-1499     1500, SACK=2000-2500 
         1000-2000     2500, SACK=1000-1500 
                                               ---------此为D-SACK 
数据段丢失且延迟 
         500-999         500-999       1000
         1000-1499       (延迟) 
         1500-1999       (该包丢失) 
         2000-2499       (延迟) 
         2500-2999       (该包丢失) 
         3000-3499       3000-3499     1000, SACK=3000-3500 
         1000-2499       1000-1499     1500, SACK=3000-3500 
         2000-2499     1500, SACK=2000-2500, 3000-3500 
         1000-2499     2500, SACK=1000-1500, 3000-3500 
                                             ---------此为部分D-SACK 


针对TCP时间戳PAWS漏洞的代码。 见:http://blog.chinaunix.net/uid-736168-id-376061.html 这里也可以理解原始套接字


问题:ip_queue_xmit中填充IP头的源和目的为什么使用的是路由的src dst

网桥brige vlan理解参考:http://blog.csdn.net/dog250/article/details/7354590





NAPI是linux一套最新的处理网口数据的API，据说是由于找不到更好的名字，所以称之为NAPI（New API）。它是到linux 2.5才引入的，所以很多驱动并不支持这种操作方式。
简单来说，NAPI是综合中断方式与轮询方式的技术。
中断的好处是响应及时，如果数据量较小，则不会占用太多的CPU时间；缺点是数据量大时，会产生过多中断，而每个中断都要消耗不少的cpu时间，从而导致效率反而不如轮询高。轮询方式与中断方式相反，它更适合处理大量数据，因为每次轮询不需要消耗过多cpu时间；缺点是即使只接收很少数据或不接数据时，也要占用cpu时间。
NAPI是二者的结合体，数据量低时采用中断法，数据量高时采用轮询法。平时是中断方式，当有数据到达时，会触发中断处理函数执行，中断处理函数关闭中断并开始处理函数。如果此时有数据到达，则没必要再触发中断了，因为中断处理函数中会轮询处理数据，直到没有新数据时才打开中断。
很明显，数据量很低与很高时，NAPI可以发挥中断方式与轮询方式的优点，性能较好。如果数据量不稳定，且说高不高说低不低，则NAPI会在两种方式切换上消耗不少时间，效率反而较低一些。

*/


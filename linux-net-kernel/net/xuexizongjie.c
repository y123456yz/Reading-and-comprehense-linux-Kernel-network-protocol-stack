/*
TSO，全称是TCP Segmentation Offload，我们知道通常以太网的MTU(除去14字节ETH头和4字节尾部校验值，如果加上ETH头和校验实际上是1518)是1500，除去TCP/IP的包头，TCP的MSS (Max Segment Size)大小是1460，通常情况下协议栈会对超过
1460的TCP payload进行segmentation，保证生成的IP包不超过MTU的大小，但是对于支持TSO/GSO的网卡而言，就没这个必要了，我们可以把最多64K大小的TCP payload
直接往下传给协议栈，此时IP层也不会进行segmentation，一直会传给网卡驱动，支持TSO/GSO的网卡会自己生成TCP/IP包头和帧头，这样可以offload很多协议栈上的
内存操作，checksum计算等原本靠CPU来做的工作都移给了网卡GSO是TSO的增强 http://lwn.net/Articles/188489/ ，GSO不只针对TCP，而是对任意协议，尽可能把
segmentation推后到交给网卡那一刻，此时会判断下网卡是否支持SG和GSO，如果不支持则在协议栈里做segmentation；如果支持则把payload直接发给网卡

TSO:效率的节省源于对大包只走一次协议栈，而不是多次.尽可能晚的推迟分段（segmentation), 最理想的是在网卡驱动里分段，在网卡驱动里把大包（super-packet)
拆开，组成SG list，或在一块预先分配好的内存中重组各段，然后交给网卡。tso功能只能对TCP有效，GSO是增强版本，对所有协议都有效。

参考:http://www.smithfox.com/?e=191
阻塞和非阻塞﻿
我们说 阻塞和 非阻塞 时, 要区分场合范围, 比如 Linux中说的 非阻塞I/O 和 Java的NIO1.0中的 非阻塞I/O 不是相同的概念. 从最根本来说, 阻塞就是进程 "被" 休息, CPU处理其它进程去了. 非阻塞可以理解成: 将大的整片时间的阻塞分成N多的小的阻塞,
所以进程不断地有机会 "被" CPU光顾, 理论上可以做点其它事. 看上去 Linux非阻塞I/O 要比阻塞好, 但CPU会很大机率﻿因socket没数据﻿而空转. 虽然这个进程是爽了, 但是从整个机器的效率来说, 浪费更大了

异步??
异步可以说是I/O最理想的模型: CPU的原则是, 有必要的时候才会参与, 既不浪费, 也不怠慢.
理想中的异步I/O: Application无需等待socket数据(也正是因此进程而被 "休息"), 也无需 copy socket data, 将由其它的同学(理想状态, 不是CPU) 负责将socket data copy到Appliation事先指定的内存后, 通知一声Appliation(一般是回调函数).
copy socket data, Application是不用做了, 但事情总是需要做, 不管是谁做, CPU是否还是要花费精力去参与呢?
可以用 "内存映射" 以及 DMA等方式来达到 "不用CPU去参与繁重的工作" 的目的. "内存映射﻿" 是不用copy, 而DMA是有其它芯片来代替CPU处理.


IP层尽可能快的将分组从源节点发送到目的节点，但不提供任何可靠性保证，分片标识等信息在IP层填充。TCP传输层通过定时重传和确认应答机制保证可靠传输。
分层:ARP RARP算链路层，IP ICMP IGMP算在网络层，TCP UDP算在传输层，FTP HTTP等算在应用层
网络数据通过网卡驱动发送的时候，最终是一个比特一个比特的二进制比特流传输出去的。
平时我们指的MTU等于1500指的是 IP首部+TCP首部+应用数据的总长度(不包括14字节以太头和末尾4字节校验码)
以太网首部:14字节， IP首部默认20字节(如果有IP选项，则不止)，TCP首部默认20字节，UDP首部8字节。
以太网首部中的type表示后面数据时IP还是ARP还是RARP或者PPP等链路层协议。IP中的type表示后面的是TCP UDP ICMP IGMP等，通过type区分后面接的是什么协议。网络层通过端口号来区分上层应用协议。
/etc/servers文件中存的是常用的应用程序端口及对应应用协议，例如telnet为23

套接字应用程序可以参考:http://blog.csdn.net/water_cow/article/details/7027032


//pf_inet的net_families[]为inet_family_ops，对应的套接口层ops参考inetsw_array中的inet_stream_ops inet_dgram_ops inet_sockraw_ops，传输层操作集分别为tcp_prot udp_prot raw_prot
//netlink的net_families[]netlink_family_ops，对应的套接口层ops为netlink_ops
应用层执行socket的时候，内核首先要判断是什么协议族，从而执行对应的ops(netlink_family_ops或者inet_family_ops)。不同协议族在套接口层有一个对应的sock ops(如inetsw_array中的对应ops)，传输层对应的ops为inetsw_array中tcp_prot等

套接字中本段和对端的相关信息都放在inet_sock中，可以保证和协议无关，各种协议都用该结构存储本地地址端口和对端地址端口已经连接状态等
以tcp为例，struct tcp_sock包含struct inet_connection_sock,inet_connection_sock包含 struct inet_sock，struct inet_sock包含struct sock, struct sock后面是 struct sock_common。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct tcp_sock)
以udp为例，struct udp_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct udp_sock)
以raw为例，struct raw_sock包含struct inet_sock，struct inet_sock包含struct sock， struct sock后面是 struct sock_common。。所以在struct socket里面的sk指向的开辟空间大小是sizeof(struct raw_sock)
//tcp_timewait_sock包含inet_timewait_sock，inet_timewait_sock包含sock_common
tcp_request_sock包含inet_request_sock，inet_request_sock包含request_sock
tcp_sock->inet_connection_sock->inet_sock->sock(socket里面的sk指向sock)

struct sock一般简称sk;  也检查传输控制块
struct socket一般简称为sock；
应用层socket函数会调用内核的__sock_create然后inet_create或者netlink_create
服务器端:
bind--->inet_bind或者netlink_bind 主要是把本段ip和端口添加到sock里面的本地成员中。bind的时候本地ip如果为INADDR_ANY(0)表示任意地址，如果本地端口为0，则内核inet_bind会分配一个端口
listen--->inet_listen   主要是分配连接请求块request_sock_queue。如果没有bind过的话，则为该sock分片一个端口。端口和地址信息存放在struct inet_sock中
accept--->inet_accept 默认是阻塞的，在SYSCALL_DEFINE3(accept...)中设置flag=0,而且是无限阻塞 sk->sk_rcvtimeo =MAX_SCHEDULE_TIMEOUT,如果应用层accept函数第二个参数需要获取对方地址，
则这里还要调用getname函数获取对方地址,  accept的时候内核会创建一个新的struct socket， 其中的struct sock是从这个rskq_accept_head队列上面取出来的(这个和socket函数内核调用不一样的地方是:
sys_socket的时候，struct socket和struct sock都是内核自己创建的)。accept一直阻塞，直到rskq_accept_head队列上有信息，然后取出这个struct sock结构。

send和recv的默认超时时间为无限大

客户端:socke后，直接connect，connct要做的事情是给客户端分配一个端口，然后发送syn tcp连接请求 
tcp状态变迁过程主要函数:tcp_rcv_state_process。connect发送完syn请求后，会一直等待知道3次握手完成才返回。connect内核不会创建新的套接口struct socket和struct sock
应用层设置接收和发送缓冲区尺寸的时候，内核实际上会*2

tcp sendto默认非阻塞的，sk->sk_sndtimeo		=	MAX_SCHEDULE_TIMEOUT;函数在发送的时候会检查是否tcp已经三次握手成功，如果还没建立连接则会返回出错信息。

为什么在应用层套接字发送大包数据(例如MCP中的同步)的时候，sendto或者write每次只返回部分长度大小，大包不会一次write成功，可以参考内核部分的tcp_sendmsg

套接字hashinfo管理过程:
/*
 * TCP传输层中用一个inet_hashinfo结构类型的全局变量
 * tcp_hashinfo对所有的散列表进行集中管理。
  //tcp_death_row里面的hashinfo指向变量tcp_hashinfo，也就是所有的inethash_info的头在这里
 */
/*
tcp udp和raw的hash分别存储到tcp_hashinfo  udp_table  raw_v4_hashinfo  

套接字应用层的close poll ioctl等在内核中对应的调用地方见socket_file_ops
shutdown close区别:
shutdown可以设置半连接端口或者双向全部端口，并能确保发送队列和接收队列的数据被发送接收完毕。
close只能是双向断开，如果close的时候接收队列有数据，则直接释放掉并直接发送rst而不走正常的四次挥手过程，发送队列中的数据是否发送出去还是直接释放掉需要看SO_LINGER中设置的时间，如果时间为0，发送队列数据直接释放，
如果不为0或者没有设置SO_LINGER选项，则等待数据发送完毕或者超时,见tcp_close。

//tcp_request_sock连接请求块，在连接的建立过程中使用， tcp_sock在连接建立之后，在终止之前使用，tcp_timewait_sock在终止连接过程中使用
////ipv4_specific是TCP传输层到网络层数据发送以及TCP建立过程的真正OPS，在tcp_prot->init中被赋值给inet_connection_sock->icsk_af_ops


后期学习点:poll epoll select fcntl
union {
		struct inet_hashinfo	*hashinfo; //tcp_hashinfo
		struct udp_table	*udp_table; //udp_table
		struct raw_hashinfo	*raw_hash; //raw_v4_hashinfo
	} h;

传输控制块由sk_alloc分配
套接字发送数据的时候，struct sock和SKB的关系可以通过sock_alloc_send_pskb(UDP和RAW套接字用这个)函数详细了解, skb_set_owner_w。TCP在构造SYN+ACK时使用sock_wmalloc，发送用户数据时通常使用sk_stream_alloc_skb()分配发送缓存
用于从驱动接收网卡数据的SKB是通过dev_alloc_skb或者alloc_skb进行分配, skb_set_owner_r。另外，辅助缓存(也叫选项缓存)的分配使用sock_kmalloc函数

family协议族通过sock_register注册  传输层接口tcp_prot udp_prot netlink_prot等通过proto_register注册   IP层接口通过inet_add_protocol(&icmp_protocol等注册 ，这些组成过程参考inet_init函数
查看各种协议的传输层ops以及socket层ops可以搜索数组inetsw_array

每种协议可以包含多个socket，所有诊断每种协议的一些全局信息，例如当前有多少个TCP socket，当前TCP总的内存大小等待，不应该在socket中，而在协议中,如tcp_prot udp_prot raw_prot等
	
套接字的创建  绑定 监听 在内核中的过程，以及inetsw_array  prot(tcp_prot  udp_prot  raw_prot)的关系
struct socket-->ops (inetsw_array), 然后调用到inet_bind(inet_lisent)等，然后会执行到tcp_prot(udp_prot raw_prot)中的相应bind listen accept(注意:这里面可能有些协议没有bind listen等)等

进程、文件和套接口层关系可以参考樊东东下层 P616
getsockname获取本端的地址，getpeername获取对端的地址

tcpdump使用方法:tcpdump src host 210.27.48.1 and ! 210.27.48.2 and src port 100 and dst port 200 and ! 3


//执行该函数sk_wake_async(将SIGIO或SIGURG信号发送给该套接字上的进程,这是异步I/O机制)的地方有sk_send_sigurg(接收到带外数据)，sock_def_write_space和sk_stream_write_space(发送缓冲区发生变化)，有新的数据到来(sock_def_readable)
//sock_def_error_report传输控制块发生某种错误，sock_def_wakeup传输状态发生变化。使用该功能的时候应用层需要通过fcntl(对应的系统调用函数为do_fcntl)
//通过fcntl设置F_SETOWN F_SETFL后，进行系统调用最好创建对应的fasync_struct, 创建地方在sock_fasync

http://blog.chinaunix.net/uid-13059622-id-3335321.html学习 《APUE》--UNIX环境高级编程 和《UNP》--UNIX网络编程  ，可以参考这个地址，里面有代码


加载进内核的ko文件们也是并发执行的吗? http://bbs.chinaunix.net/thread-4060983-1-1.html  需要了解内核模块加载原理:http://blog.chinaunix.net/uid-20626696-id-77689.html
内核部分哪些需要调度，以及和应用层经常之间的调度过程，可以参考这里，一定要看，很重要:http://blog.csdn.net/allen6268198/article/details/7567679
TCP为什么不需要分段的从组了，像IP从组那样? 因为TCP的头部有个序号字段，保证数据了数据包的正确性，是基于流的，

TCP首部中的校验和覆盖TCP首部和TCP数据，而IP首部的校验和只覆盖IP首部，而不覆盖IP数据报中的任何数据。
IP首部校验和字段和TCP首部校验和字段，如果接收端校验失败，不会产生差错报文，而是直接丢掉。
*/


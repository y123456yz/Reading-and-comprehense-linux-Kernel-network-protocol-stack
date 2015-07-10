
/*
这里面有linux的全套参考资料
http://bbs.chinaunix.net/thread-1930079-1-1.html
http://bbs.chinaunix.net/thread-1930079-1-1.html


netfilter 连接跟踪:http://blog.csdn.net/ye_shizhe/article/details/17331947

ip_queue netfilter 用户空间 内核空间通信  参考http://bbs.chinaunix.net/thread-2013041-1-1.html




linux内核协议栈，分层结构，BSD socket,INET socket层等，参考:http://blog.csdn.net/yming0221/article/details/7488828
http://blog.csdn.net/column/details/linux-kernel-net.html

那内核中套接字struct socket、struct sock、struct inet_sock、struct tcp_sock、struct raw_sock、struct udp_sock、struct inet_connection_sock、struct inet_timewait_sock和struct tcp_timewait_sock的关系是怎样的呢？
*struct socket这个是BSD层的socket，应用程序会用过系统调用首先创建该类型套接字，它和具体协议无关。

*struct inet_sock是INET协议族使用的socket结构，可以看成位于INET层，是struct sock的一个扩展。它的第一个属性就是struct sock结构。

*struct sock是与具体传输层协议相关的套接字，所有内核的操作都基于这个套接字。

*struct tcp_sock是TCP协议的套接字表示，它是对struct inet_connection_sock的扩展，其第一个属性就是struct inet_connection_sock inet_conn。

*struct raw_sock是原始类型的套接字表示，ICMP协议就使用这种套接字，其是对struct sock的扩展。

*struct udp_sock是UDP协议套接字表示，其是对struct inet_sock套接字的扩展。

*struct inet_connetction_sock是所有面向连接协议的套接字，是对struct inet_sock套接字扩展。


struct tcp_sock { 
         struct inet_connection_sock     inet_conn; //inet_connection_sock has to be the first member of tcp_sock
         ... 
};

inet_connection_sock - INET connection oriented sock
struct inet_connection_sock { 
         struct inet_sock           icsk_inet; //inet_sock has to be the first member!

         ... 
};

struct inet_sock - representation of INET sockets
struct inet_sock { 
         struct sock             sk; //       sk and pinet6 has to be the first two members of inet_sock ... 
};



linux内核netlink代码理解，参考地址:http://blog.chinaunix.net/uid-21768364-id-3244600.html


socket系统调用的内核分析  http://blog.chinaunix.net/uid-20357359-id-1963464.html
应用层创建socket会进入/NET目录下面的 socket.c函数   
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)

TCP三次握手  参考地址:http://blog.csdn.net/qy532846454/article/details/7882819


PF_INET协议族，应用层创建套接字，内核处理过程，参考http://jianshu.io/p/5d82a685b5b6


netlink详细流程分析，大体流程，很好:<netlink实现分析>  http://wenku.baidu.com/link?url=uUzbboQ-xcQp_7UGIdijovfc9n92beFpaccQfaj8wQ08PN_vaXBQA4ZjY44MdF3s_VbZr7ncoEdRNfjPHdS3swljlwMqw5bbeCTJI593fKS




从樊东东P119可以看出，NETFILTER架构是在IP网络层和传输层之间进行处理。





===========================================================PPP协议=========================================================================

ppp参考资料: 参考:http://blog.csdn.net/istone107/article/details/8065758
ppp内核架构图，可以参考:http://blog.csdn.net/vfatfish/article/details/9283703  Linux PPP实现源码分析
ppp从串口接收数据，在线路规程创建的时候用ppp_sync_open实现ppp_sync_process,ppp_input  数据收发流程参考http://blog.csdn.net/absurd/article/details/1596496

pppd和内核关系如下:
1.首先/dev/ttys0的时候会在内核创建线程规划结构struct asyncppp，并为其创建struct channel结构，一个串口对应一个channel。
2.把上面/dev/ppp文件的fd和channel关联。ioctl的时候，应用出现的fd会执行内核部分channel
3.创建unit，创建内核struct ppp结构，并把再次从新打开的/dev/ppp的ppp_dev_fd连接到内核对应的unit，ppp_dev_fd就和内核unit关联了。
http://blog.csdn.net/efan_linux/article/details/4594489 ppp帧的发送，可以了解ppp帧头压缩，加压缩等信息

PPP压缩相关参考:http://www.csdn123.com/html/20130308/51/d25bba0e39ecad98206ca042e8d40d98.htm PPP协议涉及到的几个典型压缩技术
TCP头部压缩  http://wenku.baidu.com/link?url=F6TfSsu4DHrakjn6uhrIUNibqnartKJu4i7PZ6SlcumCR877IKKx7hyjvH0bONRo73cMjEy48bxo1PMNbgUffa8K9yvB4z7LhJ6_4jXNb17
TCP头部压缩:http://blog.csdn.net/wisage/article/details/7059257   多链路PPP捆绑算法研究及改进文档对压缩有详细说明
从下层到上层走向:tty->asyn_ppp(线路规程 通道)->ppp部分->协议栈
从tty接受数据时有线路规程处处理，所以应该是在设置线路规程的时候获取tty数据，协议栈通过unit发送数据，会先到ppp，所以会在创建unit的时候注册发送函数
参考:Linux网络驱动开发步骤
de.pdf56页  MPP可以参考这个，该文档对LCP NCP都有详细说明  ppp
*/




/*
后续待了解知识点:
skb结构中的非线性空间，skb_shinfo
命名空间name space
软中断原理
樊东东第五章
注意netfilter钩子上究竟有哪些函数，究竟用来做什么
路由表项存储查询过程 :http://blog.csdn.net/qy532846454/article/details/7568994
理解listen(内核为inet_listen)过程中的sk_max_ack_backlog，也就是listen函数的第二个参数
select poll epoll 参考:http://blog.csdn.net/dianhuiren/article/details/6764190  http://blog.csdn.net/21aspnet/article/details/2627662
linux i/o模型 http://blog.sina.com.cn/s/blog_4697cdcd0100s3uh.html 
http://www.cnblogs.com/fora/archive/2011/06/30/2094324.html
http://www.cnblogs.com/hustcat/archive/2009/09/18/1569661.html
http://blog.csdn.net/tonyxf121/article/details/7878313
GSO TSO,参考xuexizongjie.c和http://www.cnblogs.com/yizhinantian/archive/2011/04/03/2004266.html，最好能好好理解。
http://blog.aliyun.com/673?spm=0.0.0.0.WFJJGP  学习阿里云产品中的:高性能网络编程（1）—accept建立连接?   一共是7章。
http://blog.csdn.net/russell_tao/article/details/18711023

*/


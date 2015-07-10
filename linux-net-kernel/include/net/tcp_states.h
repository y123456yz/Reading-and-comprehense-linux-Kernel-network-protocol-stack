/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol sk_state field.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_STATES_H
#define _LINUX_TCP_STATES_H

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE, //如果套接字状态不是TCP_CLOSE(套接字的初始状态，参见sock_init_data()函数)
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN, //在应用程序绑定的时候，如果端口已经被使用，并且处于这个状态，会绑定失败，见inet_csk_get_port
	TCP_CLOSING,	/* Now a valid state */

	TCP_MAX_STATES	/* Leave at the end! */
};

#define TCP_STATE_MASK	0xF

#define TCP_ACTION_FIN	(1 << 7)

enum {
	TCPF_ESTABLISHED = (1 << 1),
	TCPF_SYN_SENT	 = (1 << 2),
	TCPF_SYN_RECV	 = (1 << 3),
	TCPF_FIN_WAIT1	 = (1 << 4),
	TCPF_FIN_WAIT2	 = (1 << 5),
	TCPF_TIME_WAIT	 = (1 << 6),
	TCPF_CLOSE	 = (1 << 7),
	TCPF_CLOSE_WAIT	 = (1 << 8),
	TCPF_LAST_ACK	 = (1 << 9),
	TCPF_LISTEN	 = (1 << 10),
	TCPF_CLOSING	 = (1 << 11) 
};

#endif	/* _LINUX_TCP_STATES_H */

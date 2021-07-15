// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.h
 *
 *  TeaVPN2 server core header for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H
#define SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H


#include <stdalign.h>
#include <stdatomic.h>

#include <bluetea/lib/mutex.h>

#include <teavpn2/base.h>
#include <teavpn2/stack.h>
#include <teavpn2/tcp_pkt.h>
#include <teavpn2/liburing.h>
#include <teavpn2/allocator.h>
#include <teavpn2/server/auth.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 			"%s:%d (%s) (cli_idx=%u)"
#define PKT_SIZE		(sizeof(struct tsrv_pkt))
#define UPTR(NUM)		((void *)((uintptr_t)(NUM)))
#define SPTR(NUM)		((void *)((intptr_t)(NUM)))

struct client_slot {
#if USE_IO_URING
	/* This must be the first member. */
	iou_rbuf_t				__iou_rbuf_type;
#endif

	bool					is_authenticated;
	bool					is_encrypted;
	int					cli_fd;
	char					username[0x100u];

	/* Human readable src_ip and src_port */
	char					src_ip[IPV4_L + 1u];
	uint16_t				src_port;

	/* `idx` is the index where it's stored in the client slot array. */
	uint16_t				idx;

	uint16_t				err_count;
	struct teavpn2_version			ver;
	struct bt_mutex				lock;

	/* `recv_s` is the valid bytes in the below union buffer. */
	size_t					recv_s;
	union {
		/*
		 * This union is mainly for recv() operation from cli_fd, or
		 * udp_fd when are using UDP socket.
		 */
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};


struct srv_state;


struct srv_thread {
	/* Is this thread online? */
	_Atomic(bool)				is_online;

#if USE_IO_URING
	/*
	 * I am not sure it is safe to call io_uring_queue_exit()
	 * on uninitialized `struct io_uring` instance. So this
	 * @ring_init exists to make sure we only do queue exit
	 * if the io uring context has been initialized.
	 */
	bool					ring_init;

	/* IO uring instance. */
	struct io_uring				ring;

	/* IO uring wait timeout. */
	struct __kernel_timespec		ring_timeout;

	/* IO uring buffer array. */
	struct iou_rbuf_dd			*iou_rbuf_arr;

	/* Stack to keep track free IO uring buffer array index. */
	struct tv_stack				iou_rbuf_stk;
#endif

	pthread_t				thread;

	struct srv_state			*state;

	int					tun_fd;

	/* `idx` is the index where it's stored in the thread array. */
	uint16_t				idx;

	/* `read_s` is the valid bytes in the below union buffer. */
	size_t					read_s;
	union {
		/*
		 * This union is mainly for read() operation from tun_fd.
		 */
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};


#if USE_IO_URING
union iou_rbuf_uni {
	iou_rbuf_t				type;
	struct iou_rbuf_dd			dd;
	struct client_slot			client;
};

static_assert(offsetof(struct client_slot, __iou_rbuf_type) == 0,
	      "Bad offsetof(struct client_slot, __iou_rbuf_type)");

static_assert(offsetof(struct iou_rbuf_dd, type) == 0,
	      "Bad offsetof(struct iou_rbuf_dd, type)");

static_assert(offsetof(union iou_rbuf_uni, type) == 0,
	      "Bad offsetof(union iou_rbuf_uni, type)");
#endif /* #if USE_IO_URING */


enum srv_evt_loop {
	EVT_LOOP_EPOLL		= 0,
	EVT_LOOP_IO_URING	= 1
};


struct accept_data {
	int					acc_fd;
	socklen_t				addrlen;
	struct sockaddr_in			addr;
};


struct srv_state {
	/* Interrupt signal. */
	int					intr_sig;

	/* Main TCP/UDP file descriptor. */
	union {
		int				tcp_fd;
		int				udp_fd;
	};

	/* Index of thread to be assigned. */
	_Atomic(uint32_t)			tr_assign;

	/* Number of online threads. */
	_Atomic(uint32_t)			online_tr;

	/* Client slot array. */
	struct client_slot			*clients;
	struct tv_stack				cl_stk;

	/* Array of tun fds. */
	int					*tun_fds;

	/* Thread array. */
	struct srv_thread			*threads;

	/* Pointer to server config struct. */
	struct srv_cfg				*cfg;

	/* accept() variables. */
	struct accept_data			acc;

	/* Event loop type. */
	enum srv_evt_loop			event_loop;

	/* Indicate event loop needs to be stopped or not. */
	bool					stop;

	/* Do we need to delete virtual network interface ip config? */
	bool					need_ifd;

	struct sigaction			sa;
};


static inline void reset_client_state(struct client_slot *client, size_t idx)
{
#if USE_IO_URING
	client->__iou_rbuf_type   = IOU_RBUF_DD_TCP_RECV;
#endif
	client->is_authenticated  = false;
	client->is_encrypted      = false;
	client->cli_fd            = -1;
	client->username[0]       = '_';
	client->username[1]       = '\0';
	client->src_ip[0]         = '\0';
	client->src_port          = 0u;
	client->idx               = (uint16_t)idx;
	client->err_count         = 0u;
	client->recv_s            = 0u;
}


extern void teavpn2_server_interrupt_handler(int sig);
extern int teavpn2_server_tcp_socket_setup(int cli_fd, struct srv_state *state);

#endif

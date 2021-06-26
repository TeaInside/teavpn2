// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.h
 *
 *  TeaVPN2 server core header for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef USE_IO_URING
#  if defined(IO_URING_SUPPORT) && IO_URING_SUPPORT
#    define USE_IO_URING 1
#  else
#    define USE_IO_URING 0
#  endif
#endif

#ifndef SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H
#define SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/ip.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>

#include <bluetea/lib/mutex.h>
#include <bluetea/lib/string.h>

#include <teavpn2/tcp_pkt.h>
#include <teavpn2/allocator.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>


#if USE_IO_URING
/*
 * See: https://github.com/axboe/liburing/issues/366
 */
#  if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#    pragma clang diagnostic ignored "-Wshorten-64-to-32"
#    pragma clang diagnostic ignored "-Wsign-conversion"
#  endif
#  include <liburing.h>
#  if defined(__clang__)
#    pragma clang diagnostic pop
#  endif
#  define RING_QUE_NOP		(1u << 0u)
#  define RING_QUE_TUN		(1u << 1u)
#  define RING_QUE_TCP		(1u << 2u)
#endif /* #if USE_IO_URING */


#define UPTR(X)			((void *)(uintptr_t)(X))
#define IPTR(X)			((void *)(intptr_t)(X))


/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 			"%s:%d (%s) (cli_idx=%u)"
#define PKT_SIZE		(sizeof(struct tcli_pkt))


struct client_slot {
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

	/* `recv_s` is the valid bytes in the below union buffer. */
	size_t					recv_s;
	alignas(64) union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	};
};


struct srv_stack {
	struct bt_mutex				lock;
	uint16_t				*arr;
	uint16_t				sp;
	uint16_t				max_sp;
};


#if USE_IO_URING

#define IO_RING_RBUF_NUM (100u)

struct srv_iou_rbuf {
	uint32_t				idx;
	size_t					send_len;
	alignas(64) union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	};
};
#endif


struct srv_thread {
	_Atomic(bool)				is_online;
#if USE_IO_URING
	bool					ring_init;
#endif
	pthread_t				thread;
	struct srv_state			*state;
#if USE_IO_URING
	struct io_uring				ring;
	struct __kernel_timespec		ring_timeout;
	struct srv_stack			ring_buf_stk;
	struct srv_iou_rbuf			*ring_buf_arr;
#endif
	int					tun_fd;

	/* `idx` is the index where it's stored in the thread array. */
	uint16_t				idx;

	/* `read_s` is the valid bytes in the below union buffer. */
	size_t					read_s;

	alignas(64) union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	};
};


struct accept_data {
	int					acc_fd;
	socklen_t				addrlen;
	struct sockaddr_in			addr;
};


enum srv_evt_loop {
	EVT_LOOP_EPOLL		= 0,
	EVT_LOOP_IO_URING	= 1,
};


struct srv_state {
	int					intr_sig;
	int					tcp_fd;
	_Atomic(uint32_t)			tr_assign;
	_Atomic(uint32_t)			online_tr;

	/* Array of tun fds */
	int					*tun_fds;

	/* Client slot array */
	struct client_slot			*clients;

	/* Thread array */
	struct srv_thread			*threads;

	struct srv_cfg				*cfg;

	struct accept_data			acc;
	struct srv_stack			cl_stk;
	bool					stop;
	enum srv_evt_loop			event_loop;
};


static inline void reset_client_state(struct client_slot *client, size_t idx)
{
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


static inline int32_t srstk_push(struct srv_stack *cl_stk, uint16_t idx)
{
	uint16_t sp = cl_stk->sp;

	if (unlikely(sp == 0))
		/*
		 * Stack is full.
		 */
		return -1;

	cl_stk->arr[--sp] = idx;
	cl_stk->sp = sp;
	return (int32_t)idx;
}


static inline int32_t srstk_pop(struct srv_stack *cl_stk)
{
	int32_t ret;
	uint16_t sp = cl_stk->sp;
	uint16_t max_sp = cl_stk->max_sp;

	assert(sp <= max_sp);
	if (unlikely(sp == max_sp))
		/*
		 * Stack is empty.
		 */
		return -1;

	ret = (int32_t)cl_stk->arr[sp++];
	cl_stk->sp = sp;
	return ret;
}


extern int teavpn2_server_tcp_wait_threads(struct srv_state *state,
					   bool is_main);

extern int teavpn2_server_tcp_run_io_uring(struct srv_state *state);

extern int teavpn2_server_tcp_socket_setup(int cli_fd, struct srv_state *state);


#endif /* #ifndef SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H */

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

#include <fcntl.h>
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

#include <teavpn2/base.h>
#include <teavpn2/stack.h>
#include <teavpn2/tcp_pkt.h>
#include <teavpn2/allocator.h>
#include <teavpn2/server/auth.h>
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

/* Direct CQE (use the value as user_data directly (no deref)). */
#  define IOU_CQE_DRC_NOP		(1u << 0u)
#  define IOU_CQE_DRC_TUN_READ		(1u << 1u)
#  define IOU_CQE_DRC_TCP_ACCEPT	(1U << 2u)

/* Vector pending CQE */
#  define IOU_CQE_VEC_NOP		(1u << 3u)
#  define IOU_CQE_VEC_TUN_WRITE		(1u << 4u)
#  define IOU_CQE_VEC_TCP_SEND		(1u << 5u)
#  define IOU_CQE_VEC_TCP_RECV		(1u << 6u)
#endif /* #if USE_IO_URING */

/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 			"%s:%d (%s) (cli_idx=%u)"

#define PKT_SIZE		(sizeof(struct tsrv_pkt))
#define IOUCL_VEC_NUM		(4096ul)
#define UPTR(NUM)		((void *)((uintptr_t)(NUM)))

struct iou_cqe_vec {
	uint16_t				vec_type;
	uint16_t				idx;
	void					*udata;
	size_t					len;
	union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};


struct client_slot {

#if USE_IO_URING
	/* This must be the first member. */
	uint16_t				__iou_cqe_vec_type;
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
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};

union uni_iou_cqe_vec {
	uint16_t				vec_type;
	struct client_slot			client;
	struct iou_cqe_vec			send;
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
	 * if the io uring has been initialized.
	 */
	bool					ring_init;

	/* IO uring instance. */
	struct io_uring				ring;

	/* IO uring wait timeout. */
	struct __kernel_timespec		ring_timeout;

	struct iou_cqe_vec			*cqe_vec;
	struct tv_stack				ioucl_stk;
#endif
	pthread_t				thread;

	struct srv_state			*state;

	int					tun_fd;

	/* `idx` is the index where it's stored in the thread array. */
	uint16_t				idx;

	/* `read_s` is the valid bytes in the below union buffer. */
	size_t					read_s;
	union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};


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

	/* Main TCP file descriptor. */
	int					tcp_fd;

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
	client->__iou_cqe_vec_type = IOU_CQE_VEC_TCP_RECV;
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


extern void teavpn2_server_handle_interrupt(int sig);
extern int teavpn2_server_tcp_socket_setup(int cli_fd, struct srv_state *state);
extern int teavpn2_server_tcp_event_loop_io_uring(struct srv_state *state);
extern int teavpn2_server_tcp_wait_threads(struct srv_state *state,
					   bool is_main);
extern void teavpn2_server_tcp_wait_for_thread_to_exit(struct srv_state *state,
						       bool interrupt_only);


#endif /* #ifndef SRC__TEAVPN2__SERVER__LINUX__TCP_COMMON_H */

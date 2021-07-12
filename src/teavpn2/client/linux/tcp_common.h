// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp.h
 *
 *  TeaVPN2 client core header for Linux.
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

#ifndef SRC__TEAVPN2__CLIENT__LINUX__TCP_COMMON_H
#define SRC__TEAVPN2__CLIENT__LINUX__TCP_COMMON_H

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
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/tcp.h>

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
#  define IOU_CQE_VEC_TUN_WRITE		(1u << 3u)
#  define IOU_CQE_VEC_TCP_SEND		(1u << 4u)
#  define IOU_CQE_VEC_TCP_RECV		(1u << 5u)
#endif /* #if USE_IO_URING */

#define PKT_SIZE		(sizeof(struct tsrv_pkt))
#define IOUCL_VEC_NUM		(4096ul)
#define UPTR(NUM)		((void *)((uintptr_t)(NUM)))

struct iou_cqe_vec {
	uint16_t				vec_type;
	uint16_t				idx;
	size_t					send_s;
	union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};


struct cli_state;


struct cli_thread {
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

	struct cli_state			*state;

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


enum cli_evt_loop {
	EVT_LOOP_EPOLL		= 0,
	EVT_LOOP_IO_URING	= 1
};


struct cli_state {
	/* Interrupt signal. */
	int					intr_sig;

	/* Main TCP file descriptor. */
	int					tcp_fd;

	/* Number of online threads. */
	_Atomic(uint32_t)			online_tr;

	/* Array of tun fds. */
	int					*tun_fds;

	/* Thread array. */
	struct cli_thread			*threads;

	/* Pointer to client config struct. */
	struct cli_cfg				*cfg;

	/* Event loop type. */
	enum cli_evt_loop			event_loop;

	/* Indicate event loop needs to be stopped or not. */
	bool					stop;
};


extern int teavpn2_client_tcp_event_loop_io_uring(struct cli_state *state);
extern void teavpn2_client_tcp_wait_for_thread_to_exit(struct cli_state *state,
						       bool interrupt_only);
extern  int teavpn2_client_tcp_wait_threads(struct cli_state *state,
					    bool is_main);

#endif /* #ifndef SRC__TEAVPN2__CLIENT__LINUX__TCP_COMMON_H */

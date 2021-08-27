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

#include <poll.h>
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
#  define RING_QUE_NOP		(1u << 0u)
#  define RING_QUE_TUN		(1u << 1u)
#  define RING_QUE_TCP		(1u << 2u)
#endif /* #if USE_IO_URING */


#define UPTR(X)			((void *)(uintptr_t)(X))
#define IPTR(X)			((void *)(intptr_t)(X))


#define PKT_SIZE		(sizeof(struct tsrv_pkt))


struct cli_thread {
	_Atomic(bool)				is_online;
#if USE_IO_URING
	bool					ring_init;
#endif
	pthread_t				thread;
	struct cli_state			*state;
#if USE_IO_URING
	struct io_uring				ring;
	struct __kernel_timespec		ring_timeout;
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


enum cli_evt_loop {
	EVT_LOOP_EPOLL		= 0,
	EVT_LOOP_IO_URING	= 1,
};


struct cli_state {
	int					intr_sig;
	int					tcp_fd;
	_Atomic(uint32_t)			tr_assign;
	_Atomic(uint32_t)			online_tr;

	/* Array of tun fds */
	int					*tun_fds;

	/* Client slot array */
	struct client_slot			*clients;

	/* Thread array */
	struct cli_thread			*threads;

	struct cli_cfg				*cfg;

	bool					stop;
	enum cli_evt_loop			event_loop;

	/* `recv_s` is the valid bytes in the below union buffer. */
	size_t					recv_s;
	alignas(64) union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	};
};


extern int teavpn2_client_tcp_wait_threads(struct cli_state *state,
					   bool is_main);

extern int teavpn2_client_tcp_run_io_uring(struct cli_state *state);


#endif /* #ifndef SRC__TEAVPN2__CLIENT__LINUX__TCP_COMMON_H */

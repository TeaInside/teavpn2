// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/liburing.h
 *
 *  Printing header
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

#ifndef TEAVPN2__LIBURING_H
#define TEAVPN2__LIBURING_H

/*
 * See: https://github.com/axboe/liburing/issues/366
 */
#if USE_IO_URING
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
#endif /* #if USE_IO_URING */

#include <teavpn2/tcp_pkt.h>

#define IOU_RBUF_ND_NOP			(1u << 0u)
#define IOU_RBUF_ND_TUN_READ		(1u << 1u)
#define IOU_RBUF_ND_TUN_WRITE		(1u << 2u)
#define IOU_RBUF_ND_TCP_RECV		(1u << 3u)
#define IOU_RBUF_ND_TCP_ACCEPT		(1u << 4u)

#define IOU_RBUF_DD_NOP			(1u << 5u)
#define IOU_RBUF_DD_TUN_READ		(1u << 6u)
#define IOU_RBUF_DD_TUN_WRITE		(1u << 7u)
#define IOU_RBUF_DD_TCP_SEND		(1u << 8u)
#define IOU_RBUF_DD_TCP_RECV		(1u << 9u)

#define IOU_RBUF_ND_ALL_BITS		\
(					\
	IOU_RBUF_ND_NOP		|	\
	IOU_RBUF_ND_TUN_READ	|	\
	IOU_RBUF_ND_TUN_WRITE	|	\
	IOU_RBUF_ND_TCP_RECV	|	\
	IOU_RBUF_ND_TCP_ACCEPT		\
)

#define IOU_RBUF_DD_ALL_BITS		\
(					\
	IOU_RBUF_DD_NOP		|	\
	IOU_RBUF_DD_TUN_READ	|	\
	IOU_RBUF_DD_TUN_WRITE	|	\
	IOU_RBUF_DD_TCP_SEND	|	\
	IOU_RBUF_DD_TCP_RECV		\
)

typedef unsigned iou_rbuf_t;

struct iou_rbuf_dd {
	iou_rbuf_t				type;
	uint16_t				idx;
	void					*udata;
	size_t					len;
	union {
		struct tsrv_pkt			spkt;
		struct tcli_pkt			cpkt;
		char				raw_pkt[PKT_SIZE];
	} ____cacheline_aligned_in_smp;
};

#endif /* #ifndef TEAVPN2__LIBURING_H */

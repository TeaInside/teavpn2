// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/tcp_pkt_server.h
 *
 *  TCP server packet header file for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef INTERNAL____TEAVPN2__TCP_H
#error This header must only be included from <teavpn2/tcp.h>
#endif

#ifndef TEAVPN2__TCP_PKT_SERVER_H
#define TEAVPN2__TCP_PKT_SERVER_H

#include <linux/ip.h>

#include <teavpn2/base.h>

#define TSRV_PKT_NOP		(1u << 0u)
#define TSRV_PKT_HANDSHAKE	(1u << 1u)
#define TSRV_PKT_AUTH_OK	(1u << 2u)
#define TSRV_PKT_AUTH_REJECT	(1u << 3u)
#define TSRV_PKT_IFACE_DATA	(1u << 4u)
#define TSRV_PKT_REQSYNC	(1u << 5u)
#define TSRV_PKT_CLOSE		(1u << 6u)

#define TSRV_PKT_ALL_BITS 		\
(					\
	TSRV_PKT_NOP		|	\
	TSRV_PKT_HANDSHAKE	|	\
	TSRV_PKT_AUTH_OK	|	\
	TSRV_PKT_AUTH_REJECT	|	\
	TSRV_PKT_IFACE_DATA	|	\
	TSRV_PKT_REQSYNC	|	\
	TSRV_PKT_CLOSE			\
)

typedef uint8_t tsrv_pkt_type_t;

static_assert(sizeof(tsrv_pkt_type_t) == 1, "Bad sizeof(tsrv_pkt_type_t)");


struct tsrv_pkt_handshake {
	uint8_t						need_encryption;
	uint8_t						has_min;
	uint8_t						has_max;
	uint8_t						__dummy_pad[5];
	struct teavpn2_version				cur;
	struct teavpn2_version				min;
	struct teavpn2_version				max;
};

static_assert(offsetof(struct tsrv_pkt_handshake, need_encryption) == 0,
	      "Bad offsetof(struct tsrv_pkt_handshake, need_encryption)");

static_assert(offsetof(struct tsrv_pkt_handshake, has_min) == 1,
	      "Bad offsetof(struct tsrv_pkt_handshake, has_min)");

static_assert(offsetof(struct tsrv_pkt_handshake, has_max) == 2,
	      "Bad offsetof(struct tsrv_pkt_handshake, has_max)");

static_assert(offsetof(struct tsrv_pkt_handshake, __dummy_pad) == 3,
	      "Bad offsetof(struct tsrv_pkt_handshake, __dummy_pad)");

static_assert(offsetof(struct tsrv_pkt_handshake, cur) == 8,
	      "Bad offsetof(struct tsrv_pkt_handshake, cur)");

static_assert(offsetof(struct tsrv_pkt_handshake, min) == 16,
	      "Bad offsetof(struct tsrv_pkt_handshake, min)");

static_assert(offsetof(struct tsrv_pkt_handshake, max) == 24,
	      "Bad offsetof(struct tsrv_pkt_handshake, max)");

static_assert(sizeof(struct tsrv_pkt_handshake) == 32,
	      "Bad sizeof(struct tsrv_pkt_handshake)");


struct tsrv_pkt_auth_ok {
	struct if_info					iff;
};


static_assert(offsetof(struct tsrv_pkt_auth_ok, iff) == 0,
	      "Bad offsetof(struct tsrv_pkt_handshake, iff)");

static_assert(sizeof(struct tsrv_pkt_auth_ok) == sizeof(struct if_info),
	      "Bad sizeof(struct tsrv_pkt_auth_ok)");


struct tsrv_pkt_iface_data {
	struct iphdr					hdr;
	char						data[TUN_READ_SIZE];
};


static_assert(offsetof(struct tsrv_pkt_iface_data, hdr) == 0,
	      "Bad offsetof(struct tsrv_pkt_handshake, hdr)");

static_assert(offsetof(struct tsrv_pkt_iface_data, data) ==
	      sizeof(struct iphdr),
	      "Bad offsetof(struct tsrv_pkt_handshake, data)");

static_assert(sizeof(struct tsrv_pkt_iface_data) ==
	      sizeof(struct iphdr) + TUN_READ_SIZE,
	      "Bad sizeof(struct tsrv_pkt_iface_data)");

struct tsrv_pkt {
	tsrv_pkt_type_t					type;
	uint8_t						pad_len;
	uint16_t					length;
	union {
		union {
			struct tsrv_pkt_handshake	handshake;
			struct tsrv_pkt_auth_ok		auth_ok;
			struct tsrv_pkt_iface_data	iface_data;
		};
		char					raw_buf[0x2000u];
	};
};

#define TSRV_PKT_MIN_READ (offsetof(struct tsrv_pkt, raw_buf))

static_assert(offsetof(struct tsrv_pkt, type) == 0,
	      "Bad offsetof(struct tsrv_pkt, type)");

static_assert(offsetof(struct tsrv_pkt, pad_len) == 1,
	      "Bad offsetof(struct tsrv_pkt, pad_len)");

static_assert(offsetof(struct tsrv_pkt, length) == 2,
	      "Bad offsetof(struct tsrv_pkt, length)");

static_assert(offsetof(struct tsrv_pkt, handshake) == 4,
	      "Bad offsetof(struct tsrv_pkt, handshake)");

static_assert(offsetof(struct tsrv_pkt, auth_ok) == 4,
	      "Bad offsetof(struct tsrv_pkt, auth_ok)");

static_assert(offsetof(struct tsrv_pkt, iface_data) == 4,
	      "Bad offsetof(struct tsrv_pkt, iface_data)");

static_assert(offsetof(struct tsrv_pkt, raw_buf) == 4,
	      "Bad offsetof(struct tsrv_pkt, raw_buf)");

static_assert(sizeof(struct tsrv_pkt) == 4u + 0x2000u,
	      "Bad sizeof(struct tsrv_pkt)");


#endif /* #ifndef TEAVPN2__TCP_PKT_SERVER_H */

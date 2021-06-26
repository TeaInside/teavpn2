// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/tcp_pkt_client.h
 *
 *  TCP client packet header file for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef INTERNAL____TEAVPN2__TCP_H
#error This header must only be included from <teavpn2/tcp.h>
#endif

#ifndef TEAVPN2__TCP_PKT_CLIENT_H
#define TEAVPN2__TCP_PKT_CLIENT_H

#include <linux/ip.h>

#include <teavpn2/base.h>

#define TCLI_PKT_NOP		(1u << 0u)
#define TCLI_PKT_HANDSHAKE	(1u << 1u)
#define TCLI_PKT_IFACE_DATA	(1u << 2u)
#define TCLI_PKT_REQSYNC	(1u << 3u)
#define TCLI_PKT_CLOSE		(1u << 4u)

#define TCLI_PKT_ALL_BITS 		\
(					\
	TCLI_PKT_NOP		|	\
	TCLI_PKT_HANDSHAKE	|	\
	TCLI_PKT_IFACE_DATA	|	\
	TCLI_PKT_REQSYNC	|	\
	TCLI_PKT_CLOSE			\
)

typedef uint8_t tcli_pkt_type_t;

static_assert(sizeof(tcli_pkt_type_t) == 1, "Bad sizeof(tcli_pkt_type_t)");


struct tcli_pkt_handshake {
	uint8_t						need_encryption;
	uint8_t						has_min;
	uint8_t						has_max;
	uint8_t						__dummy_pad[5];
	struct teavpn2_version				cur;
	struct teavpn2_version				min;
	struct teavpn2_version				max;
};

static_assert(offsetof(struct tcli_pkt_handshake, need_encryption) == 0,
	      "Bad offsetof(struct tcli_pkt_handshake, need_encryption)");

static_assert(offsetof(struct tcli_pkt_handshake, has_min) == 1,
	      "Bad offsetof(struct tcli_pkt_handshake, has_min)");

static_assert(offsetof(struct tcli_pkt_handshake, has_max) == 2,
	      "Bad offsetof(struct tcli_pkt_handshake, has_max)");

static_assert(offsetof(struct tcli_pkt_handshake, __dummy_pad) == 3,
	      "Bad offsetof(struct tcli_pkt_handshake, __dummy_pad)");

static_assert(offsetof(struct tcli_pkt_handshake, cur) == 8,
	      "Bad offsetof(struct tcli_pkt_handshake, cur)");

static_assert(offsetof(struct tcli_pkt_handshake, min) == 8 + 32,
	      "Bad offsetof(struct tcli_pkt_handshake, min)");

static_assert(offsetof(struct tcli_pkt_handshake, max) == 8 + 32 * 2,
	      "Bad offsetof(struct tcli_pkt_handshake, max)");

static_assert(sizeof(struct tcli_pkt_handshake) == 8 + 32 * 3,
	      "Bad sizeof(struct tcli_pkt_handshake)");


struct tcli_pkt_iface_data {
	struct iphdr					hdr;
	char						data[TUN_READ_SIZE];
};


static_assert(offsetof(struct tcli_pkt_iface_data, hdr) == 0,
	      "Bad offsetof(struct tcli_pkt_handshake, hdr)");

static_assert(offsetof(struct tcli_pkt_iface_data, data) ==
	      sizeof(struct iphdr),
	      "Bad offsetof(struct tcli_pkt_handshake, data)");

static_assert(sizeof(struct tcli_pkt_iface_data) ==
	      sizeof(struct iphdr) + TUN_READ_SIZE,
	      "Bad sizeof(struct tcli_pkt_iface_data)");

struct tcli_pkt {
	tcli_pkt_type_t					type;
	uint8_t						pad_len;
	uint16_t					length;
	union {
		union {
			struct tcli_pkt_handshake	handshake;
			struct tcli_pkt_iface_data	iface_data;
		};
		char					raw_buf[0x2000u];
	};
};

#define TCLI_PKT_MIN_READ (offsetof(struct tcli_pkt, raw_buf))

static_assert(offsetof(struct tcli_pkt, type) == 0,
	      "Bad offsetof(struct tcli_pkt, type)");

static_assert(offsetof(struct tcli_pkt, pad_len) == 1,
	      "Bad offsetof(struct tcli_pkt, pad_len)");

static_assert(offsetof(struct tcli_pkt, length) == 2,
	      "Bad offsetof(struct tcli_pkt, length)");

static_assert(offsetof(struct tcli_pkt, handshake) == 4,
	      "Bad offsetof(struct tcli_pkt, handshake)");

static_assert(offsetof(struct tcli_pkt, iface_data) == 4,
	      "Bad offsetof(struct tcli_pkt, iface_data)");

static_assert(offsetof(struct tcli_pkt, raw_buf) == 4,
	      "Bad offsetof(struct tcli_pkt, raw_buf)");

static_assert(sizeof(struct tcli_pkt) == 4u + 0x2000u,
	      "Bad sizeof(struct tcli_pkt)");


#endif /* #ifndef TEAVPN2__TCP_PKT_CLIENT_H */

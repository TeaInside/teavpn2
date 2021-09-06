// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__PACKET_H
#define TEAVPN2__PACKET_H

#include <stdint.h>
#include <linux/ip.h>
#include <teavpn2/common.h>


#define TCLI_PKT_HANDSHAKE		0u
#define TCLI_PKT_AUTH			1u
#define TCLI_PKT_TUN_DATA		2u
#define TCLI_PKT_REQSYNC		3u
#define TCLI_PKT_SYNC			4u
#define TCLI_PKT_CLOSE			5u
#define TCLI_PKT_PING			6u


#define TSRV_PKT_HANDSHAKE		0u
#define TSRV_PKT_AUTH_OK		1u
#define TSRV_PKT_TUN_DATA		2u
#define TSRV_PKT_REQSYNC		3u
#define TSRV_PKT_SYNC			4u
#define TSRV_PKT_CLOSE			5u
#define TSRV_PKT_HANDSHAKE_REJECT	6u
#define TSRV_PKT_AUTH_REJECT		7u



#define SIZE_ASSERT(TYPE, LEN) 						\
	static_assert(sizeof(TYPE) == (LEN),				\
		      "Bad " __stringify(sizeof(TYPE) == (LEN)))	\


#define OFFSET_ASSERT(TYPE, MEM, EQU) 					\
	static_assert(offsetof(TYPE, MEM) == (EQU),			\
		      "Bad " __stringify(offsetof(TYPE, MEM) == (EQU)))


struct pkt_handshake {
	struct teavpn2_version			cur;
	struct teavpn2_version			min;
	struct teavpn2_version			max;
};
OFFSET_ASSERT(struct pkt_handshake, cur, 0);
OFFSET_ASSERT(struct pkt_handshake, min, 32);
OFFSET_ASSERT(struct pkt_handshake, max, 64);
SIZE_ASSERT(struct pkt_handshake, 96);


#define TSRV_HREJECT_INVALID			(1u << 0u)
#define TSRV_HREJECT_VERSION_NOT_SUPPORTED	(1u << 1u)
struct pkt_handshake_reject {
	uint8_t					reason;
	char					msg[511];
};
OFFSET_ASSERT(struct pkt_handshake_reject, reason, 0);
OFFSET_ASSERT(struct pkt_handshake_reject, msg, 1);
SIZE_ASSERT(struct pkt_handshake_reject, 512);


struct pkt_auth {
	char					username[256];
	char					password[256];
};
OFFSET_ASSERT(struct pkt_auth, username, 0);
OFFSET_ASSERT(struct pkt_auth, password, 256);
SIZE_ASSERT(struct pkt_auth, 512);


struct pkt_auth_res {
	uint8_t					status;
	struct if_info				iff;
};
OFFSET_ASSERT(struct pkt_auth_res, status, 0);
OFFSET_ASSERT(struct pkt_auth_res, iff, 2);
SIZE_ASSERT(struct pkt_auth_res, 1 + 1 + sizeof(struct if_info));


struct pkt_tun_data {
	union {
		struct iphdr			iphdr;
		uint8_t				__raw[4096];
	};
};
OFFSET_ASSERT(struct pkt_tun_data, __raw, 0);
SIZE_ASSERT(struct pkt_tun_data, 4096);


/*
 * Packet structure which is sent by the server.
 */
struct srv_pkt {
	uint16_t				len;
	uint8_t					pad_len;
	uint8_t					type;
	union {
		struct pkt_handshake		handshake;
		struct pkt_auth_res		auth_res;
		struct pkt_tun_data		tun_data;
		struct pkt_handshake_reject	hs_reject;
		char				__raw[4096];
	};
};
OFFSET_ASSERT(struct srv_pkt, len, 0);
OFFSET_ASSERT(struct srv_pkt, pad_len, 2);
OFFSET_ASSERT(struct srv_pkt, type, 3);
OFFSET_ASSERT(struct srv_pkt, handshake, 4);
OFFSET_ASSERT(struct srv_pkt, auth_res, 4);
OFFSET_ASSERT(struct srv_pkt, __raw, 4);
SIZE_ASSERT(struct srv_pkt, 2 + 1 + 1 + 4096);


/*
 * Packet structure which is sent by the client.
 */
struct cli_pkt {
	uint16_t				len;
	uint8_t					pad_len;
	uint8_t					type;
	union {
		struct pkt_handshake		handshake;
		struct pkt_auth			auth;
		struct pkt_tun_data		tun_data;
		char				__raw[4096];
	};
};
OFFSET_ASSERT(struct cli_pkt, len, 0);
OFFSET_ASSERT(struct cli_pkt, pad_len, 2);
OFFSET_ASSERT(struct cli_pkt, type, 3);
OFFSET_ASSERT(struct cli_pkt, handshake, 4);
OFFSET_ASSERT(struct cli_pkt, __raw, 4);
SIZE_ASSERT(struct cli_pkt, 2 + 1 + 1 + 4096);


struct sc_pkt {
	size_t					len;
	union {
		struct cli_pkt			cli;
		struct srv_pkt			srv;
		char				__raw[sizeof(struct cli_pkt)];
	};
};

#define PKT_MIN_LEN (2 + 1 + 1)
#define PKT_MAX_LEN (sizeof(struct cli_pkt))

static_assert(sizeof(struct cli_pkt) == sizeof(struct srv_pkt),
	      "Fail to assert sizeof(struct cli_pkt) == sizeof(struct srv_pkt)");

#endif /* #ifndef TEAVPN2__PACKET_H */

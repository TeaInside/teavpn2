// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/tcp.h
 *
 *  TCP header file for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__TCP_H
#define TEAVPN2__TCP_H

#include <teavpn2/base.h>


typedef enum _tcp_ptype_t {
	TSRV_PKT_NOP		= 0u,
	TSRV_PKT_HANDSHAKE	= (1u << 0u),
	TSRV_PKT_AUTH_OK	= (1u << 1u),
	TSRV_PKT_AUTH_REJECT	= (1u << 2u),
	TSRV_PKT_IFACE_DATA	= (1u << 3u),
	TSRV_PKT_REQSYNC	= (1u << 4u),
	TSRV_PKT_CLOSE		= (1u << 5u),
} __attribute__((packed)) tcp_ptype_t;


struct tsrv_handshake {
	uint8_t					need_encryption: 1;
	uint8_t					version;
};

struct tsrv_auth_ok {
	struct if_info				iff;
};

struct tsrv_pkt {
	tcp_ptype_t				type;
	uint16_t				length;
	union {
		union {
			struct tsrv_handshake	handshake;
			struct tsrv_auth_ok	auth_ok;
			struct teavpn2_version	version;
		};
		char				raw_buf[0x2000u];
	};
};

#endif /* #ifndef TEAVPN2__TCP_H */

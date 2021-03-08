

#ifndef TEAVPN2__NET__TCP_PKT_CLIENT_H
#define TEAVPN2__NET__TCP_PKT_CLIENT_H

#include <teavpn2/base.h>
#include <teavpn2/version_t.h>

#ifndef TEAVPN2__NET__TCP_PKT_H
#  error "This file must be included from <teavpn2/net/tcp_pkt.h>"
#endif

/*
 * tsrv_pkt_type means TCP Server Packet Type
 */

typedef enum __attribute__((packed)) _tcli_pkt_type {
	TCLI_PKT_HELLO		= 0,
	TCLI_PKT_AUTH		= 1,
	TCLI_PKT_IFACA_ACK	= 2,
	TCLI_PKT_IFACE_DATA	= 3,
	TCLI_PKT_REQSYNC	= 4,
	TCLI_PKT_PING		= 5,
	TCLI_PKT_CLOSE		= 6
} tcli_pkt_type;


struct tcli_hello_pkt {
	version_t		v;
};


struct tcli_auth_pkt {
	char			uname[64];
	char			pass[64];
};


typedef struct _tcli_pkt {
	tcli_pkt_type		type;	/* Packet type    */
	uint8_t			npad;	/* Padding length */
	uint16_t		length;	/* Data length    */
	union {
		char			raw_data[4096];
		struct tcli_hello_pkt	hello_pkt;
		struct tcli_auth_pkt	auth_pkt;
	};
} tcli_pkt;


#define CLI_PKT_MIN_L (offsetof(tcli_pkt, raw_data[0]))


static_assert(sizeof(tcli_pkt_type) == 1, "Bad sizeof(tcli_pkt_type)");

static_assert(sizeof(struct tcli_hello_pkt) == sizeof(version_t),
	      "Bad sizeof(struct tcli_hello_pkt)");

static_assert(sizeof(struct tcli_auth_pkt) == 128,
	      "Bad sizeof(struct tcli_auth_pkt)");

#endif /* #ifndef TEAVPN2__NET__TCP_PKT_CLIENT_H */

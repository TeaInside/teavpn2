

#ifndef TEAVPN2__NET__TCP_PKT_SERVER_H
#define TEAVPN2__NET__TCP_PKT_SERVER_H

#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>

#ifndef TEAVPN2__NET__TCP_PKT_H
#  error "This file must be included from <teavpn2/net/tcp_pkt.h>"
#endif


/*
 * tsrv_pkt_type means TCP Client Packet Type
 */
typedef enum __attribute__((packed)) _tsrv_pkt_type {
	TSRV_PKT_WELCOME	= 0,
	TSRV_PKT_AUTH_OK	= 1,
	TSRV_PKT_AUTH_REJECT	= 2,
	TSRV_PKT_IFACE_DATA	= 3,
	TSRV_PKT_REQSYNC	= 4,
	TSRV_PKT_PING		= 5,
	TSRV_PKT_CLOSE		= 6
} tsrv_pkt_type;


/*
 * aok means Auth OK
 */
struct tsrv_aok_pkt {
	struct iface_cfg	ifc;
};


typedef struct _tsrv_pkt {
	tsrv_pkt_type		type;	/* Packet type    */
	uint8_t			npad;	/* Padding length */
	uint16_t		length;	/* Data length    */
	union {
		char			raw_data[4096];
		struct tsrv_aok_pkt	auth_ok;

		struct {
			char		__dummy0[4095];
			char		__end;
		};
	};
} tsrv_pkt;

#define UTSRV_MUL 4

typedef union _utsrv_pkt {
	tsrv_pkt		srv_pkt;
	tsrv_pkt		__pkt_chk[UTSRV_MUL];
	char			raw_buf[sizeof(tsrv_pkt) * UTSRV_MUL];
} utsrv_pkt;


#define TSRV_PKT_MIN_L	(offsetof(tsrv_pkt, raw_data[0]))
#define TSRV_PKT_MAX_L	(offsetof(tsrv_pkt, __end))
#define TSRV_PKT_RECV_L	(offsetof(utsrv_pkt, __pkt_chk[UTSRV_MUL - 1]))

static_assert(sizeof(tsrv_pkt_type) == 1, "Bad sizeof(tsrv_pkt_type)");

static_assert(sizeof(struct tsrv_aok_pkt) == sizeof(struct iface_cfg),
	      "Bad sizeof(struct tsrv_aok_pkt)");

#endif /* #ifndef TEAVPN2__NET__TCP_PKT_SERVER_H */

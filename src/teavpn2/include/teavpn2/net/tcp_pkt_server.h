

#ifndef TEAVPN2__NET__TCP_PKT_SERVER_H
#define TEAVPN2__NET__TCP_PKT_SERVER_H

#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>

#ifndef TEAVPN2__NET__TCP_PKT_H__INCLUDE
#  error "This file must be included from <teavpn2/net/tcp_pkt.h>"
#endif


/*
 * tsrv_pkt_type_t means TCP Client Packet Type
 */
typedef enum __attribute__((packed)) _tsrv_pkt_type_t {
	TSRV_PKT_WELCOME	= 0,
	TSRV_PKT_AUTH_OK	= 1,
	TSRV_PKT_AUTH_REJECT	= 2,
	TSRV_PKT_IFACE_DATA	= 3,
	TSRV_PKT_REQSYNC	= 4,
	TSRV_PKT_PING		= 5,
	TSRV_PKT_CLOSE		= 6
} tsrv_pkt_type_t;


/*
 * aok means Auth OK
 */
struct tsrv_aok_pkt {
	struct iface_cfg	ifc;
};


typedef struct _tsrv_pkt_t {
	tsrv_pkt_type_t		type;	/* Packet type    */
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
} tsrv_pkt_t;

#define UTSRV_MUL 4

typedef union _utsrv_pkt_t {
	tsrv_pkt_t		srv_pkt;
	tsrv_pkt_t		__pkt_chk[UTSRV_MUL];
	char			raw_buf[sizeof(tsrv_pkt_t) * UTSRV_MUL];
	struct {
		char		__dummy0[(sizeof(tcli_pkt_t) * UTCLI_MUL) - 1];
		char		__end;
	};
} utsrv_pkt_t;


#define TSRV_PKT_MIN_L	(offsetof(tsrv_pkt_t, raw_data))
#define TSRV_PKT_MAX_L	(offsetof(tsrv_pkt_t, __end) + 1)
#define TSRV_PKT_RECV_L	(offsetof(utsrv_pkt_t, __end) + 1)

static_assert(sizeof(tsrv_pkt_type_t) == 1, "Bad sizeof(tsrv_pkt_type_t)");

static_assert(sizeof(struct tsrv_aok_pkt) == sizeof(struct iface_cfg),
	      "Bad sizeof(struct tsrv_aok_pkt)");

#endif /* #ifndef TEAVPN2__NET__TCP_PKT_SERVER_H */

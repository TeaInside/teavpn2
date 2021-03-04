
#ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H
#define __TEAVPN2__SERVER__LINUX__TCP_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <teavpn2/auth.h>
#include <teavpn2/__base.h>
#include <teavpn2/server/linux/tcp_packet.h>


typedef enum __attribute__((packed)) _srv_tcp_pkt_type {
	SRV_PKT_BANNER		= 0,
	SRV_PKT_AUTH_OK		= 1,
	SRV_PKT_AUTH_REJECT	= 2,
	SRV_PKT_IFACE_DATA	= 3,
	SRV_PKT_REQSYNC		= 4,
	SRV_PKT_CLOSE		= 5,
} srv_tcp_pkt_type;


struct srv_banner {
	struct ver_info			cur;
	struct ver_info			min;
	struct ver_info			max;
};


struct srv_auth_ok {
	struct iface_cfg		iface;
};


struct srv_tcp_pkt {
	srv_tcp_pkt_type		type;
	uint8_t				pad_n;
	uint16_t			length;
	union {
		char			raw_data[4096];
		struct srv_banner	banner;
		struct srv_auth_ok	auth_ok;

		struct {
			char		__dummy0[4095];
			uint8_t		__end;
		};
	};
};


typedef union _srv_tcp_pkt_buf {
	struct srv_tcp_pkt		pkt;
	struct srv_tcp_pkt		__pkt_chk[4];
	char				raw[sizeof(struct srv_tcp_pkt) * 4];
} srv_tcp_pkt_buf;


/* enum _srv_tcp_pkt_type */
STATIC_ASSERT(
	sizeof(enum _srv_tcp_pkt_type) == 1,
	"Bad sizeof(enum _srv_tcp_pkt_type)"
);


/* struct srv_banner check */
STATIC_ASSERT(
	sizeof(struct srv_banner) == (sizeof(struct ver_info) * 3),
	"Bad sizeof(struct srv_banner)"
);
STATIC_ASSERT(
	offsetof(struct srv_banner, cur) == (sizeof(struct ver_info) * 0),
	"Bad offsetof(struct srv_banner, cur)"
);
STATIC_ASSERT(
	offsetof(struct srv_banner, min) == (sizeof(struct ver_info) * 1),
	"Bad offsetof(struct srv_banner, min)"
);
STATIC_ASSERT(
	offsetof(struct srv_banner, max) == (sizeof(struct ver_info) * 2),
	"Bad offsetof(struct srv_banner, max)"
);


STATIC_ASSERT(
	sizeof(struct srv_auth_ok) == sizeof(struct iface_cfg),
	"Bad sizeof(struct srv_auth_ok)"
);


/* struct srv_tcp_pkt */
STATIC_ASSERT(
	sizeof(struct srv_tcp_pkt) == (
		1	/* type   */
		+ 1	/* pad    */
		+ 2	/* length */
		+ 4096	/* data   */
	),
	"Bad sizeof(struct srv_tcp_pkt)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, type) == 0,
	"Bad offsetof(struct srv_tcp_pkt, type)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, pad_n) == 1,
	"Bad offsetof(struct srv_tcp_pkt, pad_n)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, length) == 2,
	"Bad offsetof(struct srv_tcp_pkt, length)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, raw_data) == 4,
	"Bad offsetof(struct srv_tcp_pkt, raw_data)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, banner) == 4,
	"Bad offsetof(struct srv_tcp_pkt, banner)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, auth_ok) == 4,
	"Bad offsetof(struct srv_tcp_pkt, auth_ok)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, __dummy0) == 4,
	"Bad offsetof(struct srv_tcp_pkt, __dummy0)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, __end) == 4 + 4095,
	"Bad offsetof(struct srv_tcp_pkt, __end)"
);


/* union _srv_tcp_pkt_buf */
STATIC_ASSERT(
	sizeof(union _srv_tcp_pkt_buf) == (sizeof(struct srv_tcp_pkt) * 4),
	"Bad sizeof(union _srv_tcp_pkt_buf)"
);


#define SRV_PKT_MIN_L	(offsetof(struct srv_tcp_pkt, raw_data[0]))
#define SRV_PKT_END_OFF	(offsetof(struct srv_tcp_pkt, __end))
#define SRV_PKT_DATA_L	(SRV_PKT_END_OFF - SRV_PKT_MIN_L + 1)
#define SRV_PKT_RECV_L	(sizeof(union _srv_tcp_pkt_buf))


STATIC_ASSERT(
	SRV_PKT_MIN_L == 4,
	"Bad value of SRV_PKT_MIN_L"
);
STATIC_ASSERT(
	SRV_PKT_END_OFF == 4 + 4095,
	"Bad value of SRV_PKT_END_OFF"
);
STATIC_ASSERT(
	SRV_PKT_DATA_L == 4096,
	"Bad value of SRV_PKT_DATA_L"
);
STATIC_ASSERT(
	SRV_PKT_RECV_L == (sizeof(struct srv_tcp_pkt) * 4),
	"Bad value of SRV_PKT_RECV_L"
);

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H */


#ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H
#define __TEAVPN2__SERVER__LINUX__TCP_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <teavpn2/auth.h>
#include <teavpn2/__base.h>
#include <teavpn2/server/linux/tcp_packet.h>


typedef enum __attribute__((packed)) {
	SRV_PKT_BANNER		= 0,
	SRV_PKT_AUTH_OK		= 1,
	SRV_PKT_AUTH_REJECT	= 2,
	SRV_PKT_DATA		= 3,
	SRV_PKT_CLOSE		= 4,
} srv_tcp_pkt_type;

struct srv_banner {
	struct {
		uint8_t		ver;
		uint8_t		sub_ver;
		uint8_t		sub_sub_ver;
	} cur;

	struct {
		uint8_t		ver;
		uint8_t		sub_ver;
		uint8_t		sub_sub_ver;
	} min;

	struct {
		uint8_t		ver;
		uint8_t		sub_ver;
		uint8_t		sub_sub_ver;
	} max;
};

struct srv_auth_ok {
	struct iface_cfg	iface;
};

struct srv_tcp_pkt {
	srv_tcp_pkt_type	type;
	uint8_t			__pad;
	uint16_t		length;
	union {
		char			raw_data[4096];
		struct srv_banner	banner;
		struct srv_auth_ok	auth_ok;


		struct {
			char		__dummy0[4095];
			uint8_t		__end;
		};

		struct {
			char		__dummy1[4096];
			char		__extra[4095];
			uint8_t		__end_extra;
		};
	};
};

/**
 * Note that the offsets must be calculated properly by hand and
 * must be statically asserted.
 *
 * If we have different offsets on different architecture or platform,
 * this software won't work.
 */

STATIC_ASSERT(
	sizeof(srv_tcp_pkt_type) == 1,
	"Bad sizeof(srv_tcp_pkt_type)"
);
STATIC_ASSERT(
	sizeof(struct srv_tcp_pkt) == (
		  1	/* type      */
		+ 1	/* __pad     */
		+ 2	/* length    */
		+ 4096	/* data      */
		+ 4096  /* extra     */
	),
	"Bad sizeof(struct srv_tcp_pkt)"
);
STATIC_ASSERT(
	sizeof(struct srv_banner) == 9,
	"Bad sizeof(struct srv_banner)"
);
STATIC_ASSERT(
	sizeof(struct srv_auth_ok) == sizeof(struct iface_cfg),
	"Bad sizeof(struct srv_auth_ok)"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, length) == 2,
	"Bad offset of length in struct srv_tcp_pkt"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, raw_data) == 4,
	"Bad offset of raw_data in struct srv_tcp_pkt"
);
STATIC_ASSERT(
	offsetof(struct srv_tcp_pkt, banner) == 4,
	"Bad offset of banner in struct srv_tcp_pkt"
);
STATIC_ASSERT(offsetof(struct srv_tcp_pkt, auth_ok) == 4,
	"Bad offset of auth_ok in struct srv_tcp_pkt"
);


#define SRV_PKT_MIN_RSIZ (offsetof(struct srv_tcp_pkt, raw_data))
#define SRV_PKT_END_OFF  (offsetof(struct srv_tcp_pkt, __end))
#define SRV_PKT_DATA_SIZ (SRV_PKT_END_OFF - SRV_PKT_MIN_RSIZ)
#define SRV_PKT_RSIZE	 (offsetof(struct srv_tcp_pkt, __end_extra))

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H */

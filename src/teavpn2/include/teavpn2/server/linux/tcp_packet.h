
#ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H
#define __TEAVPN2__SERVER__LINUX__TCP_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <teavpn2/auth.h>
#include <teavpn2/server/linux/tcp_packet.h>


typedef enum __attribute__((packed)) {
	SRV_PKT_BANNER		= 0,
	SRV_PKT_AUTH_OK		= 1,
	SRV_PKT_AUTH_REJECT	= 2,
	SRV_PKT_DATA		= 3,
	SRV_PKT_CLOSE		= 4,
} srv_tcp_pkt_type;

struct __attribute__((packed)) srv_banner {
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

struct __attribute__((packed)) srv_tcp_pkt {
	srv_tcp_pkt_type	type;
	uint8_t			__pad;
	uint16_t		length;
	union {
		char			raw_data[4096];
		struct srv_banner	banner;
	};
	uint8_t			__end;
};

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
		+ 1 	/* __end pad */
	),
	"Bad sizeof(struct srv_tcp_pkt)"
);

#define SRV_PKT_MIN_RSIZ (offsetof(struct srv_tcp_pkt, raw_data))
#define SRV_PKT_END_OFF  (offsetof(struct srv_tcp_pkt, __end))
#define SRV_PKT_DATA_SIZ (SRV_PKT_END_OFF - SRV_PKT_MIN_RSIZ)

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__TCP_PACKET_H */


#ifndef __TEAVPN2__CLIENT__LINUX__TCP_PACKET_H
#define __TEAVPN2__CLIENT__LINUX__TCP_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <teavpn2/auth.h>


typedef enum __attribute__((packed)) {
	CLI_PKT_HELLO	= 0,
	CLI_PKT_AUTH	= 1,
	CLI_PKT_DATA	= 2,
	CLI_PKT_CLOSE	= 3,
} cli_tcp_pkt_type;


struct __attribute__((packed)) cli_tcp_pkt {
	cli_tcp_pkt_type	type;
	uint8_t			__pad;
	uint16_t		length;
	union {
		char		raw_data[4096];
		struct auth_pkt	auth;
	};
	uint8_t			__end;
};

STATIC_ASSERT(
	sizeof(cli_tcp_pkt_type) == 1,
	"Bad sizeof(cli_tcp_pkt_type)"
);
STATIC_ASSERT(
	sizeof(struct cli_tcp_pkt) == (
		  1	/* type      */
		+ 1	/* __pad     */
		+ 2	/* length    */
		+ 4096	/* data      */
		+ 1 	/* __end pad */
	),
	"Bad sizeof(struct cli_tcp_pkt)"
);

#define CLI_PKT_MIN_RSIZ (offsetof(struct cli_tcp_pkt, raw_data))
#define CLI_PKT_END_OFF  (offsetof(struct cli_tcp_pkt, __end))
#define CLI_PKT_DATA_SIZ (CLI_PKT_END_OFF - CLI_PKT_MIN_RSIZ)

#endif /* #ifndef __TEAVPN2__CLIENT__LINUX__TCP_PACKET_H */

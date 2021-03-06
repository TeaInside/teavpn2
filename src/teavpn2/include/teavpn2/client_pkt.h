
#ifndef __TEAVPN2__CLIENT_PKT_H
#define __TEAVPN2__CLIENT_PKT_H

#include <teavpn2/__base.h>

typedef enum __attribute__((packed)) _cli_pkt_type {
	CLI_PKT_HELLO		= 0,
	CLI_PKT_AUTH		= 1,
	CLI_PKT_IFACE_ACK	= 2,
	CLI_PKT_IFACE_FAIL	= 3,
	CLI_PKT_IFACE_DATA	= 4,
	CLI_PKT_REQSYNC		= 5,
	CLI_PKT_CLOSE		= 6
} cli_pkt_type;



struct cli_pkt {
	cli_pkt_type		type;
	uint8_t			pad;
	uint16_t		cksum;
	uint16_t		length;
	union {
		char		raw_data[4096];
	};
};

#endif /* #ifndef __TEAVPN2__CLIENT_PKT_H */

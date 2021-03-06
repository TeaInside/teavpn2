
#ifndef __TEAVPN2__SERVER_PKT_H
#define __TEAVPN2__SERVER_PKT_H

#include <teavpn2/__base.h>

typedef enum __attribute__((packed)) _srv_pkt_type {
	SRV_PKT_WELCOME		= 0,
	SRV_PKT_AUTH_OK		= 1,
	SRV_PKT_AUTH_REJECT	= 2,
	SRV_PKT_IFACE_DATA	= 3,
	SRV_PKT_REQSYNC		= 4,
	SRV_PKT_CLOSE		= 5,
} srv_pkt_type;


#endif /* #ifndef __TEAVPN2__SERVER_PKT_H */

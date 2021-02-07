

#ifndef __TEAVPN2__CLIENT__COMMON_H
#define __TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/global/common.h>

#define TEAVPN_CLIENT_VERSION "0.2.0"

struct cli_iface_cfg {
	uint16_t	mtu;			/* Virtual interface MTU     */
	char		*dev;			/* Virtual interface name    */
};


struct cli_sock_cfg {
	sock_type	type;		/* Socket type (TCP/UDP) */
	char		*server_addr;	/* Server address        */
	uint16_t	server_port;	/* Server port           */
};


struct cli_cfg {
	char			*cfg_file;  /* Config file     */
	char			*data_dir;  /* Data directory  */
	struct cli_iface_cfg	iface;
	struct cli_sock_cfg 	sock;
};

#endif /* #ifndef __TEAVPN2__CLIENT__COMMON_H */

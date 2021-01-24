

#ifndef __TEAVPN2__SERVER__COMMON_H
#define __TEAVPN2__SERVER__COMMON_H

#include <teavpn2/global/common.h>


struct srv_iface_cfg {
	uint16_t	mtu;			/* Virtual interface MTU     */
	char		*dev;			/* Virtual interface name    */
	char		ipv4_c[IPV4LEN];	/* IPv4 to be used by server */
	char		ipv4_sb_c[IPV4LEN];	/* IPv4 subnet mask          */

#ifdef TEAVPN_IPV6_SUPPORT
	char		ipv6_c[IPV6LEN];	/* IPv6 to be used by server */
	char		ipv4_sb_c[IPV6LEN];	/* IPv6 subnet mask          */
#endif
};


struct srv_sock_cfg {
	sock_type	type;		/* Socket type (TCP/UDP) */
	char		*bind_addr;	/* Bind address          */
	uint16_t	bind_port;	/* Bind port             */
	uint16_t	max_conn;	/* Max connections       */
	int		backlog;	/* Socket backlog        */
};


struct srv_cfg {
	char			*cfg_file;  /* Config file. */
	struct srv_iface_cfg	iface;
	struct srv_sock_cfg 	sock;
};

#endif /* #ifndef __TEAVPN2__SERVER__COMMON_H */


#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/__base.h>

struct srv_iface_cfg {
	uint16_t	mtu;			/* Virtual interface MTU     */
	char		*dev;			/* Virtual interface name    */
	char		*ipv4;			/* IPv4 to be used by server */
	char		*ipv4_netmask;		/* IPv4 netmask              */
#ifdef TEAVPN_IPV6_SUPPORT
	char		*ipv6;			/* IPv6 to be used by server */
	char		*ipv4_netmask;		/* IPv6 netmask              */
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
	char			*cfg_file;  /* Config file     */
	char			*data_dir;  /* Data directory  */
	struct srv_iface_cfg	iface;
	struct srv_sock_cfg 	sock;
};


int teavpn_server_entry(int argc, char *argv[]);
int teavpn_server_cfg_parse(struct srv_cfg *cfg);
int teavpn_server_argv_parse(int argc, char *argv[], struct srv_cfg *cfg);
void teavpn_server_show_help(const char *app);
void teavpn_server_show_version(void);

#endif /* #ifndef TEAVPN2__SERVER__COMMON_H */


#ifndef __TEAVPN2__CLIENT__COMMON_H
#define __TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/__base.h>


struct cli_iface_cfg {
	uint16_t	mtu;		/* Virtual interface MTU     */
	char		*dev;		/* Virtual interface name    */
};


struct cli_sock_cfg {
	sock_type	type;		/* Socket type (TCP/UDP) */
	char		*server_addr;	/* Server address        */
	uint16_t	server_port;	/* Server port           */
};


struct cli_auth_cfg {
	char		*username;
	char		*password;
};

struct cli_cfg {
	char			*cfg_file;  /* Config file     */
	char			*data_dir;  /* Data directory  */
	struct cli_iface_cfg	iface;
	struct cli_sock_cfg 	sock;
	struct cli_auth_cfg	auth;
};

int teavpn_client_entry(int argc, char *argv[]);
int teavpn_client_cfg_parse(struct cli_cfg *cfg);
int teavpn_client_argv_parse(int argc, char *argv[], struct cli_cfg *cfg);
void teavpn_client_show_help(const char *app);
void teavpn_client_show_version(void);
int teavpn_client_tcp(struct cli_cfg *cfg);

#endif /* #ifndef __TEAVPN2__CLIENT__COMMON_H */

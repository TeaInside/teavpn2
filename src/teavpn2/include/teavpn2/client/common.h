
#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/base.h>


struct cli_iface_cfg {
	char		*dev;		/* Virtual interface name    */
};


struct cli_sock_cfg {
	char		*server_addr;	/* Server address        */
	uint16_t	server_port;	/* Server port           */
	struct_pad(0, sizeof(sock_type) - sizeof(uint16_t));
	sock_type	type;		/* Socket type (TCP/UDP) */
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


extern char d_cli_cfg_file[];

/* Default config for virtual network interface */
extern char d_cli_dev[];

/* Default config for socket */
extern sock_type d_cli_sock_type;
extern char d_cli_server_addr[];
extern uint16_t d_cli_server_port;

#endif /* #ifndef TEAVPN2__CLIENT__COMMON_H */

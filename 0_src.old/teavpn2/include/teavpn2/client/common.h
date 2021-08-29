// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/client/common.h
 *
 *  Common header for TeaVPN2 client.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/base.h>


struct cli_sys_cfg {
	char			*cfg_file;
	char			*data_dir;
	uint8_t			verbose_level;
	uint16_t		thread;
};


struct cli_sock_cfg {
	bool			use_encrypt;
	sock_type		type;
	char			*server_addr;
	uint16_t		server_port;
	char			*event_loop;
};


struct cli_iface_cfg {
	char			dev[IFACENAMESIZ];

	/*
	 * Only used when net down and reconnect
	 * (this is filled by the server)
	 */
	struct if_info		iff;
};


struct cli_auth_cfg {
	char			username[0x100];
	char			password[0x100];
};


struct cli_cfg {
	struct cli_sys_cfg	sys;
	struct cli_sock_cfg	sock;
	struct cli_iface_cfg	iface;
	struct cli_auth_cfg	auth;
};


int teavpn2_run_client(int argc, char *argv[]);
int teavpn2_client_parse_argv(int argc, char *argv[], struct cli_cfg *cfg);
int teavpn2_client_load_config(struct cli_cfg *cfg);
void teavpn2_client_config_dump(struct cli_cfg *cfg);

#endif /* #ifndef TEAVPN2__CLIENT__COMMON_H */

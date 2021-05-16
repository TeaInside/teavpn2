// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/server/common.h
 *
 *  Common header for TeaVPN2 server.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/base.h>


struct srv_sys_cfg {
	char			*cfg_file;
	char			*data_dir;
	uint8_t			verbose_level;
	uint16_t		thread;
};


struct srv_sock_cfg {
	bool			use_encrypt;
	sock_type		type;
	char			*bind_addr;
	uint16_t		bind_port;
	uint16_t		max_conn;
	int			backlog;
	char			*ssl_cert;
	char			*ssl_priv_key;
};


struct srv_cfg {
	struct srv_sys_cfg	sys;
	struct srv_sock_cfg	sock;
	struct if_info		iface;
};


int teavpn2_run_server(int argc, char *argv[]);
int teavpn2_server_parse_argv(int argc, char *argv[], struct srv_cfg *cfg);
int teavpn2_server_load_config(struct srv_cfg *cfg);
void teavpn2_server_config_dump(struct srv_cfg *cfg);

#endif /* #ifndef TEAVPN2__SERVER__COMMON_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/common.h>

struct cli_cfg_sys {
	const char		*cfg_file;
	char			data_dir[128];
	uint8_t			thread_num;
	uint8_t			verbose_level;
};


struct cli_cfg_sock {
	bool			use_encryption;
	sock_type		type;
	char			server_addr[64];
	uint16_t		server_port;
	char			event_loop[64];
	uint16_t		max_conn;
	int			backlog;
};


struct cli_cfg_iface {
	bool			override_default;
	char			dev[IFACENAMESIZ];

	/*
	 * Only used when net down and reconnect
	 * (this is filled by the server).
	 */
	struct if_info		iff;
};


struct cli_cfg_auth {
	char			username[TVPN_MAX_UNAME_LEN];
	char			password[TVPN_MAX_PASS_LEN];
};


struct cli_cfg {
	struct cli_cfg_sys	sys;
	struct cli_cfg_sock	sock;
	struct cli_cfg_iface	iface;
	struct cli_cfg_auth	auth;
};

extern int teavpn2_client_udp_run(struct cli_cfg *cfg);

#endif

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/common.h>

struct cli_cfg_sys {
	const char		*cfg_file;
	const char		*data_dir;
	uint8_t			verbose_level;
	uint8_t			thread_num;
};


struct cli_cfg_sock {
	bool			use_encrypt;
	sock_type		type;
	const char		*server_addr;
	uint16_t		server_port;
	const char		*event_loop;
};


struct cli_iface_cfg {
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
	struct cli_iface_cfg	iface;
	struct cli_cfg_auth	auth;
};

#endif

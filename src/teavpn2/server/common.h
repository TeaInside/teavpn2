// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/common.h>

struct srv_cfg_sys {
	const char		*cfg_file;
	char			data_dir[128];
	uint8_t			thread_num;
	uint8_t			verbose_level;
};


struct srv_cfg_sock {
	bool			use_encryption;
	int			backlog;
	sock_type		type;
	char			bind_addr[64];
	uint16_t		bind_port;
	uint16_t		max_conn;
	char			event_loop[64];
	char			ssl_cert[256];
	char			ssl_priv_key[256];
};


struct srv_cfg_iface {
	char			dev[IFACENAMESIZ];
	uint16_t		mtu;
	struct if_info		iff;
};


struct srv_cfg {
	struct srv_cfg_sys	sys;
	struct srv_cfg_sock	sock;
	struct srv_cfg_iface	iface;
};

extern int teavpn2_server_udp_run(struct srv_cfg *cfg);

#endif

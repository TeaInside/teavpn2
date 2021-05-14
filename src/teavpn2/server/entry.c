// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/entry.c
 *
 *  Entry point for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/server/common.h>

#if defined(__linux__)
#  include <teavpn2/server/linux/tcp.h>
#endif

int teavpn2_run_server(int argc, char *argv[])
{
	int ret;
	struct srv_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	ret = teavpn2_server_parse_argv(argc, argv, &cfg);
	if (unlikely(ret))
		goto out;

	ret = teavpn2_server_load_config(&cfg);
	if (unlikely(ret))
		goto out;

	teavpn2_server_config_dump(&cfg);

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn2_server_tcp(&cfg);
	case SOCK_UDP:
		pr_err("UDP socket is not yet supported");
		return -ESOCKTNOSUPPORT;
	}
	pr_err("Invalid socket type: %d\n", cfg.sock.type);
	ret = -EINVAL;
out:
	return ret;
}

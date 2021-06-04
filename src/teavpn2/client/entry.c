// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/entry.c
 *
 *  Entry point for TeaVPN2 client
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/client/common.h>

#if defined(__linux__)
#  include <teavpn2/client/linux/tcp.h>
#endif

int teavpn2_run_client(int argc, char *argv[])
{
	int ret;
	struct cli_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	ret = teavpn2_client_parse_argv(argc, argv, &cfg);
	if (unlikely(ret))
		goto out;

	ret = teavpn2_client_load_config(&cfg);
	if (unlikely(ret))
		goto out;

	teavpn2_client_config_dump(&cfg);

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn2_client_tcp(&cfg);
	case SOCK_UDP:
		pr_err("UDP socket is not yet supported");
		return -ESOCKTNOSUPPORT;
	}
	pr_err("Invalid socket type: %u\n", cfg.sock.type);
	ret = -EINVAL;
out:
	return ret;
}

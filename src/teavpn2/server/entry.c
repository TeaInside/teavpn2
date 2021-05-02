// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/entry.c
 *
 *  Entry point for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/server/common.h>


int teavpn2_run_server(int argc, char *argv[])
{
	int ret;
	struct srv_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	ret = teavpn2_argv_parse(argc, argv, &cfg);
	if (!ret)
		goto out;


out:
	return ret;
}

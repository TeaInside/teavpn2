// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/client/tcp.c
 *
 *  TCP handler for TeaVPN2 client
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/client/tcp.h>


int teavpn_client_tcp(struct cli_cfg *cfg)
{
	return teavpn_client_tcp_handler(cfg);
}

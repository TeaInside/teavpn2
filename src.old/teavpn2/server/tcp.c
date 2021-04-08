// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/server/tcp.c
 *
 *  TCP handler for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/server/tcp.h>


int teavpn_server_tcp(struct srv_cfg *cfg)
{
	return teavpn_server_tcp_handler(cfg);
}

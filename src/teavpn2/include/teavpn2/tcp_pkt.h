// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/tcp.h
 *
 *  TCP header file for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__TCP_H
#define TEAVPN2__TCP_H

#include <teavpn2/base.h>


#define TUN_READ_SIZE	(0x1000u)

#define INTERNAL____TEAVPN2__TCP_H
#include <teavpn2/tcp_pkt_server.h>
#include <teavpn2/tcp_pkt_client.h>
#undef INTERNAL____TEAVPN2__TCP_H

static_assert(sizeof(struct tsrv_pkt) == sizeof(struct tcli_pkt),
	      "sizeof(struct tsrv_pkt) must be equal to "
	      "sizeof(struct tcli_pkt)");

#endif /* #ifndef TEAVPN2__TCP_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/client/tcp.h
 *
 *  TCP client header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__TCP_H
#define TEAVPN2__CLIENT__TCP_H

#include <teavpn2/base.h>
#include <teavpn2/client/common.h>


int teavpn_client_tcp(struct cli_cfg *cfg);
int teavpn_client_tcp_handler(struct cli_cfg *cfg);

#endif /* #ifndef TEAVPN2__CLIENT__TCP_H */

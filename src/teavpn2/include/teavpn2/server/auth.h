// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/server/auth.h
 *
 *  Auth function header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__AUTH_H
#define TEAVPN2__SERVER__AUTH_H

#include <teavpn2/tcp_pkt.h>

extern bool teavpn2_server_auth(const struct tcli_pkt_auth *auth,
				struct tsrv_pkt_auth_res *auth_res);


#endif /* #ifndef TEAVPN2__SERVER__AUTH_H */

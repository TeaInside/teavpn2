// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/include/auth.h
 *
 *  Authentication
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__AUTH_H
#define TEAVPN2__AUTH_H

#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/server/common.h>


struct auth_ret {
	struct iface_cfg	iface;
};

bool teavpn_server_auth(struct srv_cfg *cfg, struct auth_ret *ret, char *uname,
			char *pass);

static_assert(sizeof(struct iface_cfg) == sizeof(struct auth_ret),
	      "Bad sizeof(struct auth_ret)");

#endif /* #ifndef TEAVPN2__AUTH_H */

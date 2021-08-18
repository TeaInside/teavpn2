// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/client/common.h>
#include <teavpn2/client/linux/udp.h>


int teavpn2_client_udp_run(struct cli_cfg *cfg)
{
	int ret = 0;
	struct cli_udp_state *state;

	/* This is a large struct, don't use stack. */
	state = calloc_wrp(1, sizeof(*state));
	if (unlikely(!state)) {
		return -ENOMEM;
	}

	return ret;
}

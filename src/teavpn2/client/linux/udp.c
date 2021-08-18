// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/linux/udp.h>


static int init_state(struct cli_udp_state *state)
{
	int ret = 0;
	state->udp_fd = -1;
	return ret;
}


static int init_socket(struct cli_udp_state *state)
{
	int ret = 0;
	int udp_fd;
	udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (unlikely(udp_fd < 0)) {
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0): " PRERF,
			PREAR(ret));
		return -ret;
	}
	return ret;
}


static int init_iface(struct cli_udp_state *state)
{
	int ret = 0;
	return ret;
}


int teavpn2_client_udp_run(struct cli_cfg *cfg)
{
	int ret = 0;
	struct cli_udp_state *state;

	/* This is a large struct, don't use stack. */
	state = calloc_wrp(1ul, sizeof(*state));
	if (unlikely(!state))
		return -ENOMEM;

	state->cfg = cfg;
	ret = init_state(state);
	if (unlikely(ret))
		goto out;
	ret = init_socket(state);
	if (unlikely(ret))
		goto out;
	ret = init_iface(state);
	if (unlikely(ret))
		goto out;
out:
	al64_free(state);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/linux/udp.h>


int teavpn2_udp_server_epoll(struct srv_udp_state *state)
{
	int ret = 0;

	// ret = init_epoll_user_data(state);
	// if (unlikely(ret))
	// 	goto out;

	// ret = init_epoll_thread_data(state);
	// if (unlikely(ret))
	// 	goto out;

	// state->stop = false;
	// ret = run_event_loop(state);
// out:
	// destroy_epoll(state);
	return ret;
}

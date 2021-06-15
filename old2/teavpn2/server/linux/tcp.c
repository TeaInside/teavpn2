// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TeaVPN2 server core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/ip.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <linux/if_tun.h>
#include <teavpn2/lock.h>
#include <teavpn2/tcp_pkt.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

#include <bluetea/lib/string.h>


struct srv_thread {
	_Atomic(bool)			active;
	pthread_t			pthread;
};


struct srv_state {
	/*
	 * Interrupt signal value.
	 */
	int				intr_sig;

	int				tcp_fd;
	int				*tun_fds;
	struct srv_thread		*threads;
};


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret;
	struct srv_state *state;

	state = malloc(sizeof(*state));
	if (unlikely(!state)) {
		pr_err("malloc(): Cannot allocate memory");
		return -ENOMEM;
	}
	memset(state, 0, sizeof(*state));

	state->cfg = cfg;
	g_state    = state;

	ret = init_state(state);
	if (unlikely(ret))
		goto out;

	ret = init_iface(state);
	if (unlikely(ret))
		goto out;

	ret = init_tcp_socket(state);
	if (unlikely(ret))
		goto out;

	ret = run_workers(state);
out:
	wait_for_threads(state);
	destroy_state(state);
	free(state);
	return ret;
}

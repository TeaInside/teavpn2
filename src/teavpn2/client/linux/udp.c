// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/client/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/udp.h>


static int init_tun_fds(struct cli_udp_state *state)
{
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	int *tun_fds = calloc_wrp((size_t)nn, sizeof(*tun_fds));

	if (unlikely(!tun_fds))
		return -errno;

	for (i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int select_event_loop(struct cli_udp_state *state)
{
	struct cli_cfg_sock *sock = &state->cfg->sock;
	const char *evtl = sock->event_loop;

	if ((evtl[0] == '\0') || (!strcmp(evtl, "epoll"))) {
		state->evt_loop = EVTL_EPOLL;
	} else if (!strcmp(evtl, "io_uring") ||
		   !strcmp(evtl, "io uring") ||
		   !strcmp(evtl, "iouring") ||
		   !strcmp(evtl, "uring")) {
		state->evt_loop = EVTL_IO_URING;
	} else {
		pr_err("Invalid socket event loop: \"%s\"", evtl);
		return -EINVAL;
	}
	return 0;
}


static int init_state(struct cli_udp_state *state)
{
	int ret;

	prl_notice(2, "Initializing client state...");
	state->udp_fd = -1;

	ret = init_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = select_event_loop(state);
	if (unlikely(ret))
		return ret;

	switch (state->evt_loop) {
	case EVTL_EPOLL:
		state->epl_threads = NULL;
		break;
	case EVTL_IO_URING:
		break;
	case EVTL_NOP:
	default:
		panic("Aiee... invalid event loop value (%u)", state->evt_loop);
		__builtin_unreachable();
	}

	prl_notice(2, "Client state initialized successfully!");
	return ret;
}


static int init_socket(struct cli_udp_state *state)
{
	int ret = 0;
	int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (unlikely(udp_fd < 0)) {
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0): " PRERF,
			PREAR(ret));
		return -ret;
	}
	state->udp_fd = udp_fd;
	return ret;
}


static int init_iface(struct cli_udp_state *state)
{
	const char *dev = state->cfg->iface.dev;
	int ret = 0, tun_fd, *tun_fds = state->tun_fds;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

	prl_notice(2, "Initializing virtual network interface...");

	for (i = 0; i < nn; i++) {
		prl_notice(4, "Initializing tun_fds[%hhu]...", i);

		tun_fd = tun_alloc(dev, flags);
		if (unlikely(tun_fd < 0)) {
			pr_err("tun_alloc(\"%s\", %d): " PRERF, dev, flags,
				PREAR(-tun_fd));
			ret = tun_fd;
			goto err;
		}

		ret = fd_set_nonblock(tun_fd);
		if (unlikely(ret < 0)) {
			pr_err("fd_set_nonblock(%d): " PRERF, tun_fd,
				PREAR(-ret));
			close(tun_fd);
			goto err;
		}

		tun_fds[i] = tun_fd;
		prl_notice(4, "Successfully initialized tun_fds[%hhu] (fd=%d)",
			   i, tun_fd);
	}

	prl_notice(2, "Virtual network interface initialized successfully!");
	return ret;
err:
	while (i--) {
		close(tun_fds[i]);
		tun_fds[i] = -1;
	}
	return ret;
}


static int run_client_event_loop(struct cli_udp_state *state)
{
	switch (state->evt_loop) {
	case EVTL_EPOLL:
		return teavpn2_udp_epoll(state);
	case EVTL_IO_URING:
		pr_err("run_client_event_loop() with io_uring: " PRERF,
			PREAR(EOPNOTSUPP));
		return -EOPNOTSUPP;
	case EVTL_NOP:
	default:
		panic("Aiee... invalid event loop value (%u)", state->evt_loop);
		__builtin_unreachable();
	}
}


static void close_tun_fds(struct cli_udp_state *state)
{
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	int *tun_fds = state->tun_fds;
	for (i = 0; i < nn; i++) {
		if (tun_fds[i] != -1) {
			prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i,
				   tun_fds[i]);
		}
	}
	al64_free(tun_fds);
}


static void destroy_state(struct cli_udp_state *state)
{
	close_tun_fds(state);
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
	ret = run_client_event_loop(state);
out:
	destroy_state(state);
	al64_free(state);
	return ret;
}

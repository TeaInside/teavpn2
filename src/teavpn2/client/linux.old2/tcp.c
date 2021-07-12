// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp.c
 *
 *  TeaVPN2 client core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "./tcp_common.h"


/*
 * For interrupt only!
 */
static struct cli_state *g_state = NULL;


static void handle_interrupt(int sig)
{
	struct cli_state *state = g_state;

	if (state->intr_sig != -1)
		return;

	printf("\nInterrupt caught: %d\n", sig);
	if (state) {
		state->stop = true;
		state->intr_sig = sig;
		return;
	}

	panic("Bug: handle_interrupt is called when g_state is NULL\n");
}


static int validate_cfg(struct cli_state *state)
{
	const char *evtl;
	struct cli_cfg *cfg = state->cfg;

	if (!cfg->sys.thread) {
		pr_err("Number of thread cannot be zero");
		return -EINVAL;
	}

	if (!cfg->sock.server_addr || !*cfg->sock.server_addr) {
		pr_err("cfg->sock.server_addr cannot be empty");
		return -EINVAL;
	}

	if (!cfg->sock.server_port) {
		pr_err("cfg->sock.server_port cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.dev) {
		pr_err("cfg->iface.dev cannot be empty");
		return -EINVAL;
	}


	evtl = cfg->sock.event_loop;

	if (!evtl || !strcmp(evtl, "epoll")) {
		pr_notice("Using epoll event loop");
		state->event_loop = EVT_LOOP_EPOLL;
	} else if (!strcmp(evtl, "io_uring")) {
#if USE_IO_URING
		pr_notice("Using io_uring event loop");
		state->event_loop = EVT_LOOP_IO_URING;
#else
		pr_err("io_uring is not supported in this binary");
		return -EINVAL;
#endif
	} else {
		pr_err("Invalid event loop \"%s\"", evtl);
		return -EINVAL;
	}


	return 0;
}


static int init_state_threads(struct cli_state *state)
{
	struct cli_thread *threads, *thread;
	struct cli_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	threads = calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++) {
		thread = &threads[i];
		thread->idx   = (uint16_t)i;
		thread->state = state;
	}

	state->threads = threads;
	return 0;
}


static int init_state_tun_fds(struct cli_state *state)
{
	int *tun_fds;
	struct cli_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	tun_fds = calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state(struct cli_state *state)
{
	int ret;

	state->intr_sig    = -1;
	state->tcp_fd      = -1;
	state->tun_fds     = NULL;
	state->clients     = NULL;
	state->stop        = false;
	atomic_store_explicit(&state->tr_assign, 0, memory_order_relaxed);
	atomic_store_explicit(&state->online_tr, 0, memory_order_relaxed);

	ret = validate_cfg(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	pr_notice("Setting up interrupt handler...");
	signal(SIGINT, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);
	pr_notice("My PID: %d", getpid());
	return ret;
}


static void close_tun_fds(int *tun_fds, size_t nn)
{
	if (!tun_fds)
		return;

	for (size_t i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;

		prl_notice(3, "Closing tun_fds[%zu] (%d)...", i, tun_fds[i]);
		close(tun_fds[i]);
	}
}


static void destroy_state(struct cli_state *state)
{
	prl_notice(3, "Closing tcp_fd (%d)...", state->tcp_fd);
	close(state->tcp_fd);
	close_tun_fds(state->tun_fds, state->cfg->sys.thread);
	al64_free(state->tun_fds);
	al64_free(state->threads);
	al64_free(state->clients);
}


int teavpn2_client_tcp(struct cli_cfg *cfg)
{
	int ret = 0;
	struct cli_state *state;

	state = al64_malloc(sizeof(*state));
	if (unlikely(!state)) {
		ret = errno;
		pr_err("malloc(): " PRERF, PREAR(ret));
		return -ret;
	}
	memset(state, 0, sizeof(*state));

	ret = init_state(state);
	if (unlikely(ret))
		goto out;

	ret = init_iface(state);
	if (unlikely(ret))
		goto out;

	ret = init_tcp_socket(state);
	if (unlikely(ret))
		goto out;

out:
	destroy_state(state);
	al64_free(state);
	return ret;
}

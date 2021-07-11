// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TeaVPN2 server core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "./tcp_common.h"


/*
 * For interrupt only!
 */
static struct srv_state *g_state = NULL;


static void handle_interrupt(int sig)
{
	struct srv_state *state = g_state;

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


static int validate_cfg(struct srv_state *state)
{
	struct srv_cfg *cfg = state->cfg;

	if (!cfg->sys.thread) {
		pr_err("Number of thread cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.dev) {
		pr_err("cfg->iface.dev cannot be empty");
		return -EINVAL;
	}

	if (!cfg->iface.mtu) {
		pr_err("cfg->iface.mtu cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.ipv4) {
		pr_err("cfg->iface.ipv4 cannot be empty");
		return -EINVAL;
	}

	if (!*cfg->iface.ipv4_netmask) {
		pr_err("cfg->iface.ipv4_netmask cannot be empty");
		return -EINVAL;
	}


	{
		/*
		 * Validate event loop.
		 */
		const char *evtl = cfg->sock.event_loop;

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
	}

	return 0;
}


static int init_state_tun_fds(struct srv_state *state)
{
	int *tun_fds;
	struct srv_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	tun_fds = calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state_client_slot_array(struct srv_state *state)
{
	struct client_slot *clients;
	size_t nn = state->cfg->sock.max_conn;

	clients = calloc_wrp(nn, sizeof(*clients));
	if (unlikely(!clients))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		reset_client_state(&clients[i], i);

	state->clients = clients;
	return 0;
}


static int init_state_threads(struct srv_state *state)
{
	struct srv_thread *threads, *thread;
	struct srv_cfg *cfg = state->cfg;
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


static int init_state_client_stack(struct srv_state *state)
{
	int32_t ret;
	uint16_t *arr;
	size_t nn = state->cfg->sock.max_conn;
	struct srv_stack *cl_stk = &state->cl_stk;

	arr = calloc_wrp(nn, sizeof(*arr));
	if (unlikely(!arr))
		return -ENOMEM;

	ret = bt_mutex_init(&cl_stk->lock, NULL);
	if (unlikely(ret)) {
		pr_err("mutex_init(&cl_stk->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}

	cl_stk->sp = (uint16_t)nn;
	cl_stk->max_sp = (uint16_t)nn;
	cl_stk->arr = arr;

#ifndef NDEBUG
/*
 * Test only.
 */
{
	/*
	 * Push stack.
	 */
	for (size_t i = 0; i < nn; i++) {
		ret = srv_stk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}

	/*
	 * Push full stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srv_stk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}

	/*
	 * Pop stack.
	 */
	for (size_t i = nn; i--;) {
		ret = srv_stk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}


	/*
	 * Pop empty stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srv_stk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}
}
#endif
	while (nn--)
		srv_stk_push(cl_stk, (uint16_t)nn);

	BT_ASSERT(cl_stk->sp == 0);
	return 0;
}


static int init_state(struct srv_state *state)
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

	ret = init_state_client_slot_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_client_stack(state);
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


static int init_iface(struct srv_state *state)
{
	size_t i;
	int *tun_fds = state->tun_fds;
	size_t nn = state->cfg->sys.thread;
	struct if_info *iff = &state->cfg->iface;
	const short tun_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

	prl_notice(3, "Allocating virtual network interface...");
	for (i = 0; i < nn; i++) {
		int tmp_fd;

		prl_notice(5, "Allocating TUN fd %zu...", i);
		tmp_fd = tun_alloc(iff->dev, tun_flags);
		if (unlikely(tmp_fd < 0))
			return tmp_fd;

		tun_fds[i] = tmp_fd;
	}

	if (unlikely(!teavpn_iface_up(iff))) {
		pr_err("Cannot bring virtual network interface up");
		return -ENETDOWN;
	}

	return 0;
}


__no_inline
int teavpn2_server_tcp_socket_setup(int cli_fd, struct srv_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;

	y = 1;
	ret = setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(ret)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}


	y = 6;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}


	y = 50000;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	/*
	 * Don't make it non-block when we are working
	 * with io_uring.
	 */
	if (state->event_loop != EVT_LOOP_IO_URING) {
		ret = fd_set_nonblock(cli_fd);
		if (unlikely(ret < 0))
			return ret;
	}

	/*
	 * TODO: Use cfg to set some socket options.
	 */
	(void)cfg;
	return ret;
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return ret;
}


static int socket_setup_main_tcp(int tcp_fd, struct srv_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;


	y = 1;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	/*
	 * TODO: Use cfg to set some socket options.
	 */
	(void)cfg;
	return teavpn2_server_tcp_socket_setup(tcp_fd, state);
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return ret;
}


static int init_tcp_socket(struct srv_state *state)
{
	int ret;
	int type;
	int tcp_fd;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;

	type = SOCK_STREAM;
	if (state->event_loop != EVT_LOOP_IO_URING)
		type |= SOCK_NONBLOCK;

	prl_notice(0, "Creating TCP socket...");
	tcp_fd = socket(AF_INET, type, IPPROTO_TCP);
	if (unlikely(tcp_fd < 0)) {
		ret = errno;
		pr_err("socket(): " PRERF, PREAR(ret));
		return -ret;
	}


	prl_notice(0, "Setting socket file descriptor up...");
	ret = socket_setup_main_tcp(tcp_fd, state);
	if (unlikely(ret < 0))
		goto out_err;


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);
	ret = bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("bind(): " PRERF, PREAR(ret));
		goto out_err;
	}


	ret = listen(tcp_fd, sock->backlog);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("listen(): " PRERF, PREAR(ret));
		goto out_err;
	}

	state->tcp_fd = tcp_fd;
	pr_notice("Listening on %s:%d...", sock->bind_addr, sock->bind_port);

	return 0;
out_err:
	close(tcp_fd);
	return -ret;
}


static void wait_for_threads_to_exit(struct srv_state *state)
{
	int sig = SIGTERM;
	const uint32_t max_secs = 30; /* Wait for max_secs seconds. */
	const uint32_t max_iter = max_secs * 10;
	const uint32_t per_iter = 100000;
	uint32_t iter = 0;

	if (atomic_load(&state->online_tr) > 0)
		pr_notice("Waiting for thread(s) to exit...");

	if (!state->threads)
		return;

do_kill:
	for (size_t i = 0; i < state->cfg->sys.thread; i++) {
		int ret;

		/*
		 * Skip the main thread.
		 */
		if (unlikely(i == 0))
			continue;

		if (!atomic_load(&state->threads[i].is_online))
			continue;

		ret = pthread_kill(state->threads[i].thread, sig);
		if (ret) {
			pr_err("pthread_kill(threads[%zu], %s) " PRERF,
			       i, (sig == SIGTERM) ? "SIGTERM" : "SIGKILL",
			       PREAR(ret));
		}
	}


	while (atomic_load(&state->online_tr) > 0) {
		usleep(per_iter);
		if (iter++ >= max_iter)
			break;
	}


	/*
	 * We have been waiting for `max_secs`, but
	 * the threads haven't given us the offline
	 * signal through the online thread counter.
	 *
	 * Let's force kill the threads!
	 */
	if (atomic_load(&state->online_tr) > 0) {
		sig = SIGKILL;
		pr_notice("Warning: %u thread(s) haven't exited after %u seconds",
			  atomic_load(&state->online_tr), max_secs);
		pr_emerg("Killing thread(s) forcefully with SIGKILL...");
		atomic_store(&state->online_tr, 0);
		goto do_kill;
	}
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


static void close_threads(struct srv_thread *threads, size_t nn)
{
	if (!threads)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct srv_thread *thread = &threads[i];
#if USE_IO_URING
		if (thread->ring_init)
			io_uring_queue_exit(&thread->ring);
#endif
	}
}


static void close_clients(struct client_slot *clients, size_t nn)
{
	if (!clients)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct client_slot *client = &clients[i];
		int cli_fd = client->cli_fd;

		if (cli_fd == -1)
			continue;

		prl_notice(3, "Closing clients[%zu].cli_fd (%d)...", i, cli_fd);
		close(cli_fd);
	}
}


static void close_fds(struct srv_state *state)
{
	int tcp_fd = state->tcp_fd;

	close_tun_fds(state->tun_fds, state->cfg->sys.thread);
	if (tcp_fd != -1) {
		prl_notice(3, "Closing state->tcp_fd (%d)...", tcp_fd);
		close(tcp_fd);
	}
	close_clients(state->clients, state->cfg->sock.max_conn);
}


static void destroy_state(struct srv_state *state)
{
	close_fds(state);
	close_threads(state->threads, state->cfg->sys.thread);
	bt_mutex_destroy(&state->cl_stk.lock);
	al64_free(state->cl_stk.arr);
	al64_free(state->tun_fds);
	al64_free(state->threads);
	al64_free(state->clients);
}


int teavpn2_server_tcp_wait_threads(struct srv_state *state, bool is_main)
{
	size_t tr_num = state->cfg->sys.thread;

	if (tr_num == 1)
		/* 
		 * Don't wait, we are single threaded.
		 */
		return 0;


	if (is_main) {
		pr_notice("Waiting for threads to be ready...");
		while (likely(atomic_load(&state->online_tr) < tr_num)) {
			if (unlikely(state->stop))
				return -EINTR;
			usleep(50000);
		}
		pr_notice("Threads are all ready!");
		pr_notice("Initialization Sequence Completed");
		return 0;
	} else {
		struct srv_thread *mt = &state->threads[0];
		while (likely(!atomic_load(&mt->is_online))) {
			if (unlikely(state->stop))
				return -EINTR;
			usleep(50000);
		}
		return -EALREADY;
	}
}


static int run_event_loop(struct srv_state *state)
{
	switch (state->event_loop) {
	case EVT_LOOP_EPOLL:
		return 0;
	case EVT_LOOP_IO_URING:
#if USE_IO_URING
		return teavpn2_server_tcp_run_io_uring(state);
#else
		pr_err("io_uring is not supported in this binary");
		return -EINVAL;
#endif
	}
	__builtin_unreachable();
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret = 0;
	struct srv_state *state;

	state = al64_malloc(sizeof(*state));
	if (unlikely(!state)) {
		ret = errno;
		pr_err("malloc(): " PRERF, PREAR(ret));
		return -ret;
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

	ret = run_event_loop(state);
out:
	wait_for_threads_to_exit(state);
	destroy_state(state);
	al64_free(state);
	return ret;
}

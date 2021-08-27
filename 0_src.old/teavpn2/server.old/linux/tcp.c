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


void teavpn2_server_interrupt_handler(int sig)
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
	panic("handle_interrupt is called when g_state is NULL");
}


static int validate_cfg(struct srv_state *state)
{
	const char *evtl;
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

	evtl = cfg->sock.event_loop;
	/*
	 * Default use epoll.
	 */
	if (!evtl || !strcmp(evtl, "epoll")) {
		pr_notice("Using epoll event loop");
		state->event_loop = EVT_LOOP_EPOLL;
	} else if (!strcmp(evtl, "io_uring")) {
#if USE_IO_URING
		pr_notice("Using io_uring event loop");
		state->event_loop = EVT_LOOP_IO_URING;
#else
		pr_notice("io_uring is not supported in this binary");
		return -EOPNOTSUPP;
#endif
	} else {
		return -EINVAL;
	}
	return 0;
}


static int init_state_tun_fds(struct srv_state *state)
{
	int *tun_fds;
	struct srv_cfg *cfg = state->cfg;
	size_t i, nn = cfg->sys.thread;

	tun_fds = al64_calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state_clients_array(struct srv_state *state)
{
	int ret = 0;
	struct client_slot *clients;
	size_t i, nn = state->cfg->sock.max_conn;

	clients = al64_calloc_wrp(nn, sizeof(*clients));
	if (unlikely(!clients))
		return -ENOMEM;

	for (i = 0; i < nn; i++) {
		reset_client_state(&clients[i], i);
		ret = bt_mutex_init(&clients[i].lock, NULL);
		if (unlikely(ret)) {
			pr_err("bt_mutex_init(&clients[i].lock, NULL)" PRERF,
			       PREAR(ret));
			ret = -ret;
			/* Don't free, let the caller do it! */
		}
	}

	state->clients = clients;
	return ret;
}


static int init_state_threads(struct srv_state *state)
{
	struct srv_thread *threads, *thread;
	struct srv_cfg *cfg = state->cfg;
	size_t i, nn = cfg->sys.thread;

	threads = al64_calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -ENOMEM;

	for (i = 0; i < nn; i++) {
		thread        = &threads[i];
		thread->idx   = (uint16_t)i;
		thread->state = state;
	}

	state->threads = threads;
	return 0;
}


/*
 * Initialize every needed server struct member and validate the config.
 */
static int init_state(struct srv_state *state)
{
	int ret;

	state->intr_sig    = -1;
	state->tcp_fd      = -1;
	state->tun_fds     = NULL;
	state->clients     = NULL;
	state->stop        = false;
	state->need_ifd    = false;
	atomic_store_explicit(&state->tr_assign, 0, memory_order_relaxed);
	atomic_store_explicit(&state->online_tr, 0, memory_order_relaxed);

	ret = validate_cfg(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_clients_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	ret = tv_stack_init(&state->cl_stk, state->cfg->sock.max_conn);
	if (unlikely(ret))
		return ret;

	pr_notice("Setting up interrupt handler...");
	sigemptyset(&state->sa.sa_mask);
	sigaddset(&state->sa.sa_mask, SIGINT);
	sigaddset(&state->sa.sa_mask, SIGHUP);
	sigaddset(&state->sa.sa_mask, SIGTERM);
	state->sa.sa_handler = teavpn2_server_handle_interrupt;

	sigaction(SIGINT, &state->sa, NULL);
	sigaction(SIGHUP, &state->sa, NULL);
	sigaction(SIGTERM, &state->sa, NULL);
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

	state->need_ifd = true;
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


__no_inline
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


__no_inline
void teavpn2_server_tcp_wait_for_thread_to_exit(struct srv_state *state,
						bool interrupt_only)
{
	size_t i;
	int sig = SIGTERM;
	const uint32_t max_secs = 30; /* Wait for max_secs seconds. */
	const uint32_t max_iter = max_secs * 10;
	const uint32_t per_iter = 100000;
	uint32_t iter = 0;

	if ((!interrupt_only) && (atomic_load(&state->online_tr) > 0))
		pr_notice("Waiting for thread(s) to exit...");


do_kill:
	for (i = 0; i < state->cfg->sys.thread; i++) {
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


	if (interrupt_only)
		return;


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


static void close_tun_fds(struct srv_state *state, size_t nn)
{
	size_t i;
	int *tun_fds = state->tun_fds;

	if (!tun_fds)
		return;

	if (state->need_ifd) {
		pr_notice("Removing virtual network interface configuration...");
		teavpn_iface_down(&state->cfg->iface);
	}

	for (i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;

		prl_notice(3, "Closing tun_fds[%zu] (%d)...", i, tun_fds[i]);
		close(tun_fds[i]);
	}
}


static void close_clients(struct client_slot *clients, size_t nn)
{
	size_t i;

	if (!clients)
		return;

	for (i = 0; i < nn; i++) {
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

	close_tun_fds(state, state->cfg->sys.thread);
	if (tcp_fd != -1) {
		prl_notice(3, "Closing state->tcp_fd (%d)...", tcp_fd);
		close(tcp_fd);
	}
	close_clients(state->clients, state->cfg->sock.max_conn);
}


static void destroy_clients(struct client_slot *clients, size_t num)
{
	if (!clients)
		return;

	while (num--)
		bt_mutex_destroy(&clients[num].lock);
}


static void destroy_state(struct srv_state *state)
{
	close_fds(state);
	bt_mutex_destroy(&state->cl_stk.lock);
	destroy_clients(state->clients, state->cfg->sock.max_conn);
	al64_free(state->cl_stk.arr);
	al64_free(state->tun_fds);
	al64_free(state->threads);
	al64_free(state->clients);
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret;
	struct srv_state *state;

	state = al64_calloc(1, sizeof(*state));
	if (unlikely(!state)) {
		ret = errno;
		pr_err("al64_calloc(): " PRERF, PREAR(ret));
		return -ret;
	}

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
	destroy_state(state);
	al64_free(state);
	return ret;
}

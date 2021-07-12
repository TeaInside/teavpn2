// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp.c
 *
 *  TeaVPN2 client core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
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
	panic("handle_interrupt is called when g_state is NULL");
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


static int init_state_tun_fds(struct cli_state *state)
{
	int *tun_fds;
	struct cli_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	tun_fds = al64_calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state_threads(struct cli_state *state)
{
	struct cli_thread *threads, *thread;
	struct cli_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	threads = al64_calloc_wrp(nn, sizeof(*threads));
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


static int init_state(struct cli_state *state)
{
	int ret;

	state->intr_sig    = -1;
	state->tcp_fd      = -1;
	state->tun_fds     = NULL;
	state->threads     = NULL;
	state->stop        = false;
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


static int init_iface(struct cli_state *state)
{
	size_t i;
	size_t nn = 2;
	int *tun_fds = state->tun_fds;
	const char *iff_dev = state->cfg->iface.dev;
	const short tun_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

	prl_notice(3, "Allocating virtual network interface...");
	for (i = 0; i < nn; i++) {
		int tmp_fd;

		prl_notice(5, "Allocating TUN fd %zu...", i);
		tmp_fd = tun_alloc(iff_dev, tun_flags);
		if (unlikely(tmp_fd < 0))
			return tmp_fd;

		tun_fds[i] = tmp_fd;
	}

	return 0;
}


static int teavpn2_client_tcp_socket_setup(int tcp_fd, struct cli_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct cli_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;

	y = 1;
	ret = setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(ret)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}


	y = 6;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}


	y = 50000;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	if (state->event_loop != EVT_LOOP_IO_URING) {
		ret = fd_set_nonblock(tcp_fd);
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


static int socket_setup_main_tcp(int tcp_fd, struct cli_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct cli_cfg *cfg = state->cfg;
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
	return teavpn2_client_tcp_socket_setup(tcp_fd, state);
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return ret;
}


static int do_connect(struct cli_state *state)
{
	int ret;
	int err;
	int flags;
	int orig_flags;
	struct pollfd fds[1];
	struct sockaddr_in addr;
	int tcp_fd = state->tcp_fd;
	struct cli_sock_cfg *sock = &state->cfg->sock;


	orig_flags = fcntl(tcp_fd, F_GETFL, 0);
	if (unlikely(orig_flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_GETFL, 0): " PRERF, tcp_fd, PREAR(err));
		return -err;
	}


	flags = fcntl(tcp_fd, F_SETFL, orig_flags | O_NONBLOCK);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_SETFL, %d): " PRERF, tcp_fd, flags,
		       PREAR(err));
		return -err;
	}


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->server_port);
	addr.sin_addr.s_addr = inet_addr(sock->server_addr);

	pr_notice("Connecting to %s:%d...", sock->server_addr,
		  sock->server_port);


connect_again:
	ret = connect(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (!ret)
		goto out_established;

	ret = errno;
	if ((ret == EINPROGRESS) || (ret == EALREADY) || (ret == EAGAIN)) {
		time_t start;
		int intr_count = 0;
		int poll_ret;
		int timeout = 30000;
		fds[0].fd = tcp_fd;
		fds[0].events = POLLOUT;
		start = time(NULL);
		while (1) {
			poll_ret = poll(fds, 1u, timeout);
			if (!poll_ret) {
				ret = ETIMEDOUT;
				break;
			}

			if (poll_ret > 0)
				goto connect_again;

			err = errno;
			if (err == EINTR) {
				if (++intr_count >= 2) {
					pr_notice("Cancelling poll()...");
					break;
				}
				state->intr_sig = -1;
				state->stop = false;
				pr_notice("Hey, I am still connecting...");
				pr_notice("Interrupt once again to cancel!");
				pr_notice("Connecting...");
				timeout -= (int)(time(NULL) - start) * 1000;
				if (timeout < 0)
					timeout = 1;
				continue;
			}

			pr_err("poll(): " PRERF, PREAR(err));
			return err;
		}
	}

	pr_err("connect(): " PRERF, PREAR(ret));
	return ret;
	

out_established:
	prl_notice(0, "Connection established!");

	orig_flags = fcntl(tcp_fd, F_SETFL, orig_flags);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_SETFL, %d): " PRERF, tcp_fd, flags,
		       PREAR(err));
		return -err;
	}
	return 0;
}


static int init_tcp_socket(struct cli_state *state)
{
	int ret;
	int type;
	int tcp_fd;

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


	state->tcp_fd = tcp_fd;
	return do_connect(state);

out_err:
	close(tcp_fd);
	return -ret;
}


static int run_event_loop(struct cli_state *state)
{
	switch (state->event_loop) {
	case EVT_LOOP_EPOLL:
		return -1;
	case EVT_LOOP_IO_URING:
		return teavpn2_client_tcp_event_loop_io_uring(state);
	}
	__builtin_unreachable();
}


__no_inline
int teavpn2_client_tcp_wait_threads(struct cli_state *state, bool is_main)
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
		struct cli_thread *mt = &state->threads[0];
		while (likely(!atomic_load(&mt->is_online))) {
			if (unlikely(state->stop))
				return -EINTR;
			usleep(50000);
		}
		return -EALREADY;
	}
}


__no_inline
void teavpn2_client_tcp_wait_for_thread_to_exit(struct cli_state *state,
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
	int tcp_fd = state->tcp_fd;

	if (tcp_fd != -1) {
		prl_notice(3, "Closing state->tcp_fd (%d)...", tcp_fd);
		close(tcp_fd);
	}
	close_tun_fds(state->tun_fds, state->cfg->sys.thread);
	al64_free(state->tun_fds);
	al64_free(state->threads);
}


int teavpn2_client_tcp(struct cli_cfg *cfg)
{
	int ret;
	struct cli_state *state;

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

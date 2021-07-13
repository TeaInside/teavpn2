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


void teavpn2_client_handle_interrupt(int sig)
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
	sigemptyset(&state->sa.sa_mask);
	sigaddset(&state->sa.sa_mask, SIGINT);
	sigaddset(&state->sa.sa_mask, SIGHUP);
	sigaddset(&state->sa.sa_mask, SIGTERM);
	state->sa.sa_handler = teavpn2_client_handle_interrupt;
	sigaction(SIGINT, &state->sa, NULL);
	sigaction(SIGHUP, &state->sa, NULL);
	sigaction(SIGTERM, &state->sa, NULL);
	signal(SIGHUP, SIG_IGN);
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


static int wait_for_fd_be_readable(int fd, int timeout)
{
	int poll_ret;
	struct pollfd fds[1];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	poll_ret = poll(fds, 1u, timeout);

	if (poll_ret < 0)
		return -errno;

	if (!poll_ret)
		return -ETIMEDOUT;

	return 0;
}


static ssize_t do_recv_poll(int fd, void *buf_p, size_t recv_len, int try_count)
{
	ssize_t recv_ret;
	size_t recv_s = 0;
	char *recv_buf = buf_p;
	const int poll_timeout = 5000; /* In milliseconds */

do_recv:
	recv_ret = recv(fd, recv_buf + recv_s, recv_len - recv_s, 0);
	if (unlikely(recv_ret < 0)) {
		int err = errno;
		if (err != EAGAIN)
			pr_err("recv(): " PRERF, PREAR(err));
		return (ssize_t)-err;
	}

	if (unlikely(recv_ret == 0)) {
		pr_notice("Server has closed its connection");
		return -ECONNRESET;
	}

	recv_s += (size_t)recv_ret;
	pr_debug("recv_poll() rec %zd bytes (recv_s=%zu)", recv_ret, recv_s);

	if (recv_s < recv_len) {
		int ret;
		/*
		 * We haven't completely received the packet.
		 *
		 * Do recv() more, but wait until the fd is
		 * ready for it.
		 */
do_poll:
		ret = wait_for_fd_be_readable(fd, poll_timeout);
		if (ret < 0) {
			if ((ret == -ETIMEDOUT) && (try_count-- > 0))
				goto do_poll;
			return ret;
		}
		goto do_recv;
	}

	return (ssize_t)recv_s;
}


static int send_init_handshake(struct cli_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct tcli_pkt *cli_pkt = &state->threads[0].cpkt;
	struct tcli_pkt_handshake *pkt_hs = &cli_pkt->handshake;

	pkt_hs->need_encryption = false;
	pkt_hs->has_min = false;
	pkt_hs->has_max = false;
	pkt_hs->cur.ver = VERSION;
	pkt_hs->cur.patch_lvl = PATCHLEVEL;
	pkt_hs->cur.sub_lvl = SUBLEVEL;
	sane_strncpy(pkt_hs->cur.extra, EXTRAVERSION, sizeof(pkt_hs->cur.extra));

	cli_pkt->type = TCLI_PKT_HANDSHAKE;
	cli_pkt->pad_len = 0u;
	cli_pkt->length = sizeof(*pkt_hs);
	send_len = TCLI_PKT_MIN_READ + sizeof(*pkt_hs);

	send_ret = send(state->tcp_fd, cli_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		int err = errno;
		pr_err("send(): " PRERF, PREAR(err));
		return -err;
	}

	if (unlikely(((size_t)send_ret) != send_len)) {
		pr_err("send_ret != send_len");
		pr_err("send_ret = %zd", send_ret);
		pr_err("send_len = %zu", send_len);
		pr_err("Cannot initialize handshake with server");
		return -EAGAIN;
	}

	pr_notice("Handshake packet sent! (%zd bytes)", send_ret);
	return 0;
}



static int recv_init_handshake(struct cli_state *state)
{
	int try_count;
	size_t recv_len;
	ssize_t recv_ret;
	int tcp_fd = state->tcp_fd;
	struct tsrv_pkt *srv_pkt = &state->threads[0].spkt;
	struct tsrv_pkt_handshake *pkt_hss = &srv_pkt->handshake;

	try_count = 5;
	recv_len  = TCLI_PKT_MIN_READ + sizeof(*pkt_hss);
	recv_ret  = do_recv_poll(tcp_fd, srv_pkt, recv_len, try_count);
	if (unlikely(recv_ret < 0)) {
		pr_err("do_recv_poll(): " PRERF, PREAR((int)recv_ret));
		return (int)-recv_ret;
	}

	pkt_hss = &srv_pkt->handshake;
	/* For C string print safety. */
	pkt_hss->cur.extra[sizeof(pkt_hss->cur.extra) - 1] = '\0';
	pr_notice("Got protocol handshake from the server"
		  " (server version: TeaVPN2-v%hhu.%hhu.%hhu%s)",
		  pkt_hss->cur.ver,
		  pkt_hss->cur.patch_lvl,
		  pkt_hss->cur.sub_lvl,
		  pkt_hss->cur.extra);

	return 0;
}


static int send_auth(struct cli_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_cfg *cfg = state->cfg;
	struct tcli_pkt *cli_pkt = &state->threads[0].cpkt;
	struct tcli_pkt_auth *auth = &cli_pkt->auth;

	auth->ulen = (uint8_t)strlen(cfg->auth.username);
	auth->plen = (uint8_t)strlen(cfg->auth.password);
	sane_strncpy(auth->username, cfg->auth.username, sizeof(auth->username));
	sane_strncpy(auth->password, cfg->auth.password, sizeof(auth->password));

	cli_pkt->length  = sizeof(*auth);
	cli_pkt->pad_len = 0u;
	cli_pkt->type    = TCLI_PKT_AUTH;
	send_len         = TCLI_PKT_MIN_READ + sizeof(*auth);

	send_ret = send(state->tcp_fd, cli_pkt, send_len, 0);
	if (unlikely(send_ret < 0))
		return -errno;

	if (unlikely(((size_t)send_ret) != send_len)) {
		pr_err("send_ret != send_len");
		pr_err("send_ret = %zd", send_ret);
		pr_err("send_len = %zu", send_len);
		pr_err("Cannot send auth packet to server");
		return -EAGAIN;
	}

	pr_notice("Auth packet sent! (%zd bytes)", send_ret);
	return 0;
}


static int recv_auth(struct cli_state *state)
{
}


static int do_handshake(struct cli_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try_count = 5;

	pr_notice("Initializing protocol handshake...");

send_handshake:
	ret = send_init_handshake(state);
	if (unlikely(ret))
		return ret;

	pr_notice("Waiting for handshake response...");
	ret = wait_for_fd_be_readable(state->tcp_fd, 5000);
	if (ret < 0) {
		if ((ret == -ETIMEDOUT) && (++try_count < max_try_count)) {
			pr_notice("Resending handshake packet...");
			goto send_handshake;
		}
		return ret;
	}

	return recv_init_handshake(state);
}


static int do_auth(struct cli_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try_count = 5;

	pr_notice("Authenticating...");

send_auth:
	ret = send_auth(state);
	if (unlikely(ret))
		return ret;

	pr_notice("Waiting for auth response...");
	ret = wait_for_fd_be_readable(state->tcp_fd, 5000);
	if (ret < 0) {
		if ((ret == -ETIMEDOUT) && (++try_count < max_try_count)) {
			pr_notice("Resending auth packet...");
			goto send_auth;
		}
		return ret;
	}

	return recv_auth(state);
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

	ret = do_handshake(state);
	if (unlikely(ret)) {
		pr_err("do_handshake(): " PRERF, PREAR(-ret));
		goto out;
	}

	ret = do_auth(state);
	if (unlikely(ret)) {
		pr_err("do_auth(): " PRERF, PREAR(-ret));
		goto out;
	}

	ret = run_event_loop(state);
out:
	destroy_state(state);
	al64_free(state);
	return ret;
}

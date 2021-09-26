// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/udp.h>


static struct srv_udp_state *g_state = NULL;


static void signal_intr_handler(int sig)
{
	struct srv_udp_state *state;

	state = g_state;
	if (unlikely(!state)) {
		panic("signal_intr_handler is called when g_state is NULL");
		__builtin_unreachable();
	}

	if (state->sig == -1) {
		state->stop = true;
		state->sig  = sig;
		putchar('\n');
	}
}


static int alloc_tun_fds_array(struct srv_udp_state *state)
{
	int *tun_fds;
	uint8_t i, nn;

	nn      = state->cfg->sys.thread_num;
	tun_fds = calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -errno;

	for (i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int select_event_loop(struct srv_udp_state *state)
{
	struct srv_cfg_sock *sock = &state->cfg->sock;
	const char *evtl = sock->event_loop;

	if ((evtl[0] == '\0') || (!strcmp(evtl, "epoll"))) {
		state->evt_loop = EVTL_EPOLL;
	} else if (!strcmp(evtl, "io_uring") ||
		   !strcmp(evtl, "io uring") ||
		   !strcmp(evtl, "iouring")  ||
		   !strcmp(evtl, "uring")) {
		state->evt_loop = EVTL_IO_URING;
	} else {
		pr_err("Invalid socket event loop: \"%s\"", evtl);
		return -EINVAL;
	}

	switch (state->evt_loop) {
	case EVTL_EPOLL:
		state->epl_threads = NULL;
		break;
	case EVTL_IO_URING:
		state->iou_threads = NULL;
		break;
	case EVTL_NOP:
	default:
		panic("Aiee... invalid event loop value (%u)", state->evt_loop);
		__builtin_unreachable();
	}
	return 0;
}


static int init_state(struct srv_udp_state *state)
{
	int ret;

	prl_notice(2, "Initializing server state...");

	g_state       = state;
	state->udp_fd = -1;
	state->sig    = -1;

	ret = alloc_tun_fds_array(state);
	if (unlikely(ret))
		return ret;

	ret = select_event_loop(state);
	if (unlikely(ret))
		return ret;

	prl_notice(2, "Setting up signal interrupt handler...");
	if (unlikely(signal(SIGINT, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGTERM, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGHUP, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGPIPE, SIG_IGN) == SIG_ERR))
		goto sig_err;

	prl_notice(2, "Server state is initialized successfully!");
	return ret;

sig_err:
	ret = errno;
	pr_err("signal(): " PRERF, PREAR(ret));
	return -ret;
}


static int socket_setup(int udp_fd, struct srv_udp_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;


	y = 6;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}


	y = 1024 * 1024 * 50;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 100;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}


	y = 50000;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	/*
	 * TODO: Use cfg to set some socket options.
	 */
	(void)cfg;
	return ret;


out_err:
	err = errno;
	pr_err("setsockopt(udp_fd, %s, %s, %d): " PRERF, lv, on, y, PREAR(err));
	return ret;
}


static int init_socket(struct srv_udp_state *state)
{
	int ret;
	int type;
	int udp_fd;
	struct sockaddr_in addr;
	struct srv_cfg_sock *sock = &state->cfg->sock;


	type = SOCK_DGRAM;
	if (state->evt_loop != EVTL_IO_URING)
		type |= SOCK_NONBLOCK;


	prl_notice(2, "Initializing UDP socket...");
	udp_fd = socket(AF_INET, type, 0);
	if (unlikely(udp_fd < 0)) {
		const char *q = (type & SOCK_NONBLOCK) ? " | SOCK_NONBLOCK" : "";
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF, q, PREAR(ret));
		return -ret;
	}
	prl_notice(2, "UDP socket initialized successfully (fd=%d)", udp_fd);


	prl_notice(2, "Setting up socket configuration...");
	ret = socket_setup(udp_fd, state);
	if (unlikely(ret))
		goto out_err;


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);
	prl_notice(2, "Binding UDP socket to %s:%hu...", sock->bind_addr,
		   sock->bind_port);


	ret = bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("bind(): " PRERF, PREAR(ret));
		goto out_err;
	}


	state->udp_fd = udp_fd;
	return 0;


out_err:
	close(udp_fd);
	return -ret;
}


static int init_iface(struct srv_udp_state *state)
{
	uint8_t i, nn;
	int ret = 0, tun_fd, *tun_fds;
	const char *dev = state->cfg->iface.dev;
	short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;


	if (unlikely(!dev || !*dev)) {
		pr_err("iface dev cannot be empty!");
		return -EINVAL;
	}


	prl_notice(2, "Initializing virtual network interface (%s)...", dev);


	tun_fds = state->tun_fds;
	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		prl_notice(4, "Initializing tun_fds[%hhu]...", i);

		tun_fd = tun_alloc(dev, flags);
		if (unlikely(tun_fd < 0)) {
			pr_err("tun_alloc(\"%s\", %d): " PRERF, dev, flags,
			       PREAR(-tun_fd));
			ret = tun_fd;
			goto err;
		}

		if (state->evt_loop != EVTL_IO_URING) {
			ret = fd_set_nonblock(tun_fd);
			if (unlikely(ret < 0)) {
				pr_err("fd_set_nonblock(%d): " PRERF, tun_fd,
				       PREAR(-ret));
				close(tun_fd);
				goto err;
			}
		}

		tun_fds[i] = tun_fd;
		prl_notice(4, "Successfully initialized tun_fds[%hhu] (fd=%d)",
			   i, tun_fd);
	}

	if (unlikely(!teavpn_iface_up(&state->cfg->iface.iff))) {
		pr_err("teavpn_iface_up(): cannot bring up network interface");
		return -ENETDOWN;
	}

	state->need_remove_iff = true;
	prl_notice(2, "Virtual network interface initialized successfully!");
	return ret;
err:
	while (i--) {
		close(tun_fds[i]);
		tun_fds[i] = -1;
	}
	return ret;
}


static int init_udp_session_array(struct srv_udp_state *state)
{
	int ret = 0;
	struct udp_sess *sess_arr;
	uint16_t i, max_conn = state->cfg->sock.max_conn;

	prl_notice(4, "Initializing UDP session array...");
	sess_arr = calloc_wrp((size_t)max_conn, sizeof(*sess_arr));
	if (unlikely(!sess_arr))
		return -errno;

	state->sess_arr = sess_arr;
	for (i = 0; i < max_conn; i++)
		reset_udp_session(&sess_arr[i], i);

	return ret;
}


static int init_udp_session_map(struct srv_udp_state *state)
{
	int ret;
	size_t len = 0x100u * 0x100u;
	struct udp_map_bucket (*sess_map)[0x100u];

	prl_notice(4, "Initializing UDP session map...");
	sess_map = calloc_wrp(len, sizeof(struct udp_map_bucket));
	if (unlikely(!sess_map))
		return -errno;

	ret = mutex_init(&state->sess_map_lock, NULL);
	if (unlikely(ret))
		return -ret;

	state->sess_map = sess_map;
	return ret;
}


static int init_udp_session_stack(struct srv_udp_state *state)
{
	int ret;
	uint16_t i, max_conn = state->cfg->sock.max_conn;

	prl_notice(4, "Initializing UDP session stack...");
	if (unlikely(!bt_stack_init(&state->sess_stk, max_conn)))
		return -errno;

	ret = mutex_init(&state->sess_stk_lock, NULL);
	if (unlikely(ret))
		return -ret;

#ifndef NDEBUG
	for (i = 0; i < 100; i++)
		bt_stack_test(&state->sess_stk);
#endif

	for (i = max_conn; i--;) {
		int32_t tmp = bt_stack_push(&state->sess_stk, (uint16_t)i);
		if (unlikely(tmp == -1)) {
			panic("Fatal bug in init_udp_session_stack!");
			__builtin_unreachable();
		}
	}

	return 0;
}


static int init_ipv4_map(struct srv_udp_state *state)
{
	uint16_t (*ipv4_map)[0x100];

	ipv4_map = calloc_wrp(0x100ul * 0x100ul, sizeof(uint16_t));
	if (unlikely(!ipv4_map))
		return -errno;

	state->ipv4_map = ipv4_map;
	return 0;
}


static int run_server_event_loop(struct srv_udp_state *state)
{
	switch (state->evt_loop) {
	case EVTL_EPOLL:
		return teavpn2_udp_server_epoll(state);
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


static void close_udp_fd(struct srv_udp_state *state)
{
	int udp_fd = state->udp_fd;

	if (udp_fd != -1) {
		prl_notice(2, "Closing udp_fd (fd=%d)...", udp_fd);
		close(udp_fd);
	}
}


static void close_tun_fds(struct srv_udp_state *state)
{
	uint8_t i, nn;
	int *tun_fds = state->tun_fds;

	if (!tun_fds)
		return;

	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		if (tun_fd == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fd);
		close(tun_fd);
	}
}


static void close_fds_state(struct srv_udp_state *state)
{
	close_udp_fd(state);
	close_tun_fds(state);
}


static void destroy_state(struct srv_udp_state *state)
{

	if (state->threads_wont_exit)
		/*
		 * When we're exiting, the main thread will wait for
		 * the subthreads to exit for the given timeout. If
		 * the subthreads won't exit, @threads_wont_exit is
		 * set to true. This is an indicator that we are not
		 * allowed to free() and close() the resources as it
		 * may lead to UAF bug.
		 */
		return;

	close_fds_state(state);
	bt_stack_destroy(&state->sess_stk);
	al64_free(state->sess_arr);
	al64_free(state->sess_map);
	al64_free(state->ipv4_map);
	al64_free(state->tun_fds);
	al64_free(state);
}


int teavpn2_server_udp_run(struct srv_cfg *cfg)
{
	int ret;
	struct srv_udp_state *state;

	state = calloc_wrp(1ul, sizeof(*state));
	if (unlikely(!state))
		return -errno;

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
	ret = init_udp_session_array(state);
	if (unlikely(ret))
		goto out;
	ret = init_udp_session_map(state);
	if (unlikely(ret))
		goto out;
	ret = init_udp_session_stack(state);
	if (unlikely(ret))
		goto out;
	ret = init_ipv4_map(state);
	if (unlikely(ret))
		goto out;
	ret = run_server_event_loop(state);
out:
	destroy_state(state);
	return ret;
}

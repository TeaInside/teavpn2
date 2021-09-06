// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/server/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/udp.h>


static struct srv_udp_state *g_state = NULL;


static void interrupt_handler(int sig)
{
	struct srv_udp_state *state;

	state = g_state;
	if (unlikely(!state))
		panic("interrupt_handler is called when g_state is NULL");

	if (state->sig == -1) {
		state->stop = true;
		state->sig  = sig;
		putchar('\n');
	}
}


static int init_tun_fds(struct srv_udp_state *state)
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


static int select_event_loop(struct srv_udp_state *state)
{
	struct srv_cfg_sock *sock = &state->cfg->sock;
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


static int init_state(struct srv_udp_state *state)
{
	int ret;

	prl_notice(2, "Initializing server state...");
	g_state = state;
	state->udp_fd = -1;
	state->sig = -1;

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

	prl_notice(2, "Setting up interrupt handler...");
	if (signal(SIGINT, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGTERM, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGHUP, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		goto sig_err;

	prl_notice(2, "Client state initialized successfully!");
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


	y = 1024 * 1024 * 200;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 200;
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
	pr_err("setsockopt(udp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
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
	prl_notice(4, "Calling socket(AF_INET, SOCK_DGRAM%s, 0)...",
		   (type & SOCK_NONBLOCK) ? " | SOCK_NONBLOCK" : "");
	udp_fd = socket(AF_INET, type, 0);
	if (unlikely(udp_fd < 0)) {
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF,
		       (type & SOCK_NONBLOCK) ? " | SOCK_NONBLOCK" : "",
		       PREAR(ret));
		return -ret;
	}
	prl_notice(2, "UDP socket initialized successfully (fd=%d)", udp_fd);

	prl_notice(2, "Setting up socket configuration...");
	ret = socket_setup(udp_fd, state);
	if (unlikely(ret))
		goto out_err;

	prl_notice(2, "Binding UDP socket to %s:%u...", sock->bind_addr,
		   sock->bind_port);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);
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
	const char *dev = state->cfg->iface.dev;
	int ret = 0, tun_fd, *tun_fds = state->tun_fds;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

	if (unlikely(!dev || !*dev)) {
		pr_err("iface dev cannot be empty!");
		return -EINVAL;
	}

	prl_notice(2, "Initializing virtual network interface (%s)...", dev);
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
	struct udp_sess *sess;
	uint16_t i, len = UDP_SESS_NUM + 1;

	prl_notice(4, "Initializing UDP session array...");
	sess = calloc_wrp((size_t)len, sizeof(*sess));
	if (unlikely(!sess))
		return -errno;

	state->sess = sess;
	for (i = 0; i < len; i++)
		reset_udp_session(&sess[i], i);

	return ret;
}


static int init_udp_session_map(struct srv_udp_state *state)
{
	int ret;
	size_t len = 0x100u * 0x100u;
	struct udp_map_bucket (*sess_map)[0x100u];

	prl_notice(4, "Initializing UDP session map...");
	sess_map = calloc_wrp((size_t)len, sizeof(struct udp_map_bucket));
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
	size_t i;

	prl_notice(4, "Initializing UDP session stack...");
	if (unlikely(!bt_stack_init(&state->sess_stk, UDP_SESS_NUM)))
		return -errno;

	ret = mutex_init(&state->sess_stk_lock, NULL);
	if (unlikely(ret))
		return -ret;

	for (i = UDP_SESS_NUM; i--;)
		bt_stack_push(&state->sess_stk, (uint16_t)i);

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


static void close_tun_fds(struct srv_udp_state *state)
{
	uint8_t i, nn;
	int *tun_fds = state->tun_fds;

	if (!tun_fds)
		return;

	nn = (uint8_t)state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fds[i]);
	}
	al64_free(tun_fds);
}


static void close_udp_fd(struct srv_udp_state *state)
{
	if (state->udp_fd != -1) {
		prl_notice(2, "Closing udp_fd (fd=%d)...", state->udp_fd);
		close(state->udp_fd);
		state->udp_fd = -1;
	}
}


static void close_udp_sessions(struct srv_udp_state *state)
{
	uint16_t i, len = UDP_SESS_NUM + 1;
	struct udp_map_bucket (*sess_map)[0x100u] = state->sess_map;
	struct udp_sess	*sess = state->sess;

	if (!sess)
		goto free_sess_map;

	for (i = 0; i < len; i++) {
		if (sess[i].src_addr != 0)
			put_udp_session(state, &sess[i]);
	}

	al64_free(sess);
	state->sess = NULL;

free_sess_map:
	if (!sess_map)
		return;

	al64_free(sess_map);
	state->sess_map = NULL;
}


static void destroy_state(struct srv_udp_state *state)
{
	if (state->need_remove_iff) {
		prl_notice(2, "Removing virtual network interface configuration...");
		teavpn_iface_down(&state->cfg->iface.iff);
	}

	if (state->threads_wont_exit) {
		/*
		 * WARNING!!!
		 *
		 * We are exiting, but the subthreads won't exit.
		 *
		 * Having memory leak right before exit is acceptable
		 * rather than potential UAF since the thread may use
		 * the freed memory if we free it here.
		 */
		pr_emerg("Thread(s) won't exit!");
		return;
	}

	close_udp_sessions(state);
	close_tun_fds(state);
	close_udp_fd(state);

	bt_stack_destroy(&state->sess_stk);

	mutex_lock(&state->sess_stk_lock);
	mutex_unlock(&state->sess_stk_lock);
	mutex_destroy(&state->sess_stk_lock);

	mutex_lock(&state->sess_stk_lock);
	mutex_unlock(&state->sess_stk_lock);
	mutex_destroy(&state->sess_map_lock);

	al64_free(state->ipv4_map);
	al64_free(state);
}


int teavpn2_server_udp_run(struct srv_cfg *cfg)
{
	int ret = 0;
	struct srv_udp_state *state;

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

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


	y = 1024 * 1024 * 200;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 50;
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
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF,
		       ((type & SOCK_NONBLOCK) ? " | SOCK_NONBLOCK" : ""),
		       PREAR(ret));
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
	prl_notice(2, "Binding UDP socket to %s:%hu", sock->bind_addr,
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
	uint16_t i, len = state->cfg->sock.max_conn;

	prl_notice(4, "Initializing UDP session array...");
	sess_arr = calloc_wrp((size_t)len, sizeof(*sess_arr));
	if (unlikely(!sess_arr))
		return -errno;

	state->sess_arr = sess_arr;
	for (i = 0; i < len; i++)
		reset_udp_session(&sess_arr[i], i);

	return ret;
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
out:
	return ret;
}

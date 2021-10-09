// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/udp.h>


static struct cli_udp_state *g_state = NULL;


static void signal_intr_handler(int sig)
{
	struct cli_udp_state *state;

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


static int alloc_tun_fds_array(struct cli_udp_state *state)
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


static int select_event_loop(struct cli_udp_state *state)
{
	struct cli_cfg_sock *sock = &state->cfg->sock;
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


static int init_state(struct cli_udp_state *state)
{
	int ret;
	struct sc_pkt *pkt;

	prl_notice(2, "Initializing client state...");

	g_state       = state;
	state->udp_fd = -1;
	state->sig    = -1;

	ret = alloc_tun_fds_array(state);
	if (unlikely(ret))
		return ret;

	ret = select_event_loop(state);
	if (unlikely(ret))
		return ret;

	pkt = al4096_malloc_mmap(sizeof(*pkt));
	if (unlikely(!pkt))
		return -errno;

	state->pkt = pkt;

	prl_notice(2, "Setting up signal interrupt handler...");
	if (unlikely(signal(SIGINT, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGTERM, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGHUP, signal_intr_handler) == SIG_ERR))
		goto sig_err;
	if (unlikely(signal(SIGPIPE, SIG_IGN) == SIG_ERR))
		goto sig_err;

	prl_notice(2, "Client state is initialized successfully!");
	return ret;

sig_err:
	ret = errno;
	pr_err("signal(): " PRERF, PREAR(ret));
	return -ret;
}


static int socket_setup(int udp_fd, struct cli_udp_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct cli_cfg *cfg = state->cfg;
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
	return -err;
}


static int init_socket(struct cli_udp_state *state)
{
	int ret;
	int type;
	int udp_fd;
	struct sockaddr_in addr;
	struct cli_cfg_sock *sock = &state->cfg->sock;


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
	if (unlikely(ret)) {
		ret = -ret;
		goto out_err;
	}


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->server_port);
	addr.sin_addr.s_addr = inet_addr(sock->server_addr);
	prl_notice(2, "Connecting to %s:%hu (stateless)...", sock->server_addr,
		   sock->server_port);


	ret = connect(udp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("connect(): " PRERF, PREAR(ret));
		goto out_err;
	}


	state->udp_fd = udp_fd;
	return 0;


out_err:
	close(udp_fd);
	return -ret;
}


static ssize_t simple_do_send_to(int udp_fd, const void *pkt, size_t send_len)
{
	int ret;
	ssize_t send_ret;
	send_ret = sendto(udp_fd, pkt, send_len, 0, NULL, 0);
	if (unlikely(send_ret < 0)) {
		ret = errno;
		pr_err("sendto(): " PRERF, PREAR(ret));
		return -ret;
	}
	pr_debug("sendto(fd=%d) %zd bytes", udp_fd, send_ret);
	return send_ret;
}


static ssize_t simple_do_recv_from(int udp_fd, void *pkt, size_t recv_len)
{
	int ret;
	ssize_t recv_ret;
	recv_ret = recvfrom(udp_fd, pkt, recv_len, 0, NULL, 0);
	if (unlikely(recv_ret < 0)) {
		ret = errno;
		pr_err("recvfrom(): " PRERF, PREAR(ret));
		return -ret;
	}
	pr_debug("recvfrom(fd=%d) %zd bytes", udp_fd, recv_ret);
	return recv_ret;
}


static int init_iface(struct cli_udp_state *state)
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

	state->need_remove_iff = false;
	return ret;
err:
	while (i--) {
		close(tun_fds[i]);
		tun_fds[i] = -1;
	}
	return ret;
}


static int poll_fd_input(struct cli_udp_state *state, int fd, int timeout)
{
	int ret;
	nfds_t nfds = 1;
	struct pollfd fds[1];

poll_again:
	fds[0].fd = fd;
	fds[0].events = POLLIN | POLLPRI;
	ret = poll(fds, nfds, timeout);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret != EINTR)
			return -ret;

		prl_notice(2, "poll() is interrupted!");
		if (!state->stop) {
			prl_notice(2, "Executing poll() again...");
			goto poll_again;
		}
		return -ret;
	}
	if (ret == 0)
		return -ETIMEDOUT;

	return ret;
}


static int server_handshake_chk(struct srv_pkt *srv_pkt, size_t len)
{
	struct pkt_handshake *hand = &srv_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;
	const size_t expected_len = sizeof(*hand);

	if (srv_pkt->type == TSRV_PKT_CLOSE) {
		prl_notice(2, "Server has closed the connection!");
		return -ECONNRESET;
	}

	if (len < (PKT_MIN_LEN + expected_len)) {
		pr_err("Invalid handshake packet length (expected_len = %zu;"
		       " actual = %zu)", PKT_MIN_LEN + expected_len, len);
		return -EBADMSG;
	}

	srv_pkt->len = ntohs(srv_pkt->len);
	if ((size_t)srv_pkt->len != expected_len) {
		pr_err("Invalid handshake packet length (expected_len = %zu;"
		       " srv_pkt->len = %hu)", expected_len, srv_pkt->len);
		return -EBADMSG;
	}

	if (srv_pkt->type != TSRV_PKT_HANDSHAKE) {
		pr_err("Invalid packet type "
		       "(expected = TSRV_PKT_HANDSHAKE (%u);"
		       " actual = %hhu",
		       TSRV_PKT_HANDSHAKE, srv_pkt->type);
		return -EBADMSG;
	}

	/* For printing safety! */
	cur->extra[sizeof(cur->extra) - 1] = '\0';
	prl_notice(2, "Got server handshake response "
		   "(server version: TeaVPN2-%hhu.%hhu.%hhu%s)",
		   cur->ver,
		   cur->patch_lvl,
		   cur->sub_lvl,
		   cur->extra);


	if ((cur->ver != VERSION) || (cur->patch_lvl != PATCHLEVEL) ||
	    (cur->sub_lvl != SUBLEVEL)) {
	    	pr_err("Server version is not supported for this client");
		return -EBADMSG;
	}

	return 0;
}


static int _do_handshake(struct cli_udp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	int udp_fd = state->udp_fd;
	struct cli_pkt *cli_pkt = &state->pkt->cli;

	prl_notice(2, "Initializing protocol handshake...");
	send_len = cli_pprep_handshake(cli_pkt);
	send_ret = simple_do_send_to(udp_fd, cli_pkt, send_len);
	return (send_ret >= 0) ? 0 : (int)send_ret;
}


static int wait_for_handshake_response(struct cli_udp_state *state)
{
	int ret;
	ssize_t recv_ret;
	int udp_fd = state->udp_fd;
	struct srv_pkt *srv_pkt = &state->pkt->srv;

	prl_notice(2, "Waiting for server handshake response...");
	ret = poll_fd_input(state, udp_fd, 5000);
	if (unlikely(ret < 0))
		return ret;

	recv_ret = simple_do_recv_from(udp_fd, srv_pkt, PKT_MAX_LEN);
	if (unlikely(recv_ret < 0))
		return (int)recv_ret;

	return server_handshake_chk(srv_pkt, (size_t)recv_ret);
}


int teavpn2_cli_udp_send_close_packet(struct cli_udp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &state->pkt->cli;

	send_len = cli_pprep(cli_pkt, TCLI_PKT_CLOSE, 0, 0);
	send_ret = simple_do_send_to(state->udp_fd, cli_pkt, send_len);
	pr_debug("send_close_packet() = %zd", send_ret);
	return unlikely(send_ret < 0) ? (int)send_ret : 0;
}


static int do_handshake(struct cli_udp_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try = 5;

	/*
	 * Send close packet first, in case we have
	 * a stale connection, it will gets closed
	 * first.
	 */
	send_close_packet(state);
try_again:
	ret = _do_handshake(state);
	if (unlikely(ret))
		return ret;

	try_count++;
	ret = wait_for_handshake_response(state);
	if (ret == -ETIMEDOUT && try_count < max_try)
		goto try_again;

	if (ret == -ECONNRESET) {
		if (try_count >= 3) {
			prl_notice(2, "Got ECONNRESET, giving up...");
			goto out;
		}

		prl_notice(2, "Waiting for possible clean up...");
		goto try_again;
	}

out:
	return ret;
}


static int server_auth_res_chk(struct srv_pkt *srv_pkt, size_t len)
{
	struct pkt_auth_res *auth_res = &srv_pkt->auth_res;
	const size_t expected_len = sizeof(*auth_res);

	if (srv_pkt->type == TSRV_PKT_CLOSE) {
		prl_notice(2, "Server has closed the connection!");
		return -ECONNRESET;
	}

	if (srv_pkt->type == TSRV_PKT_AUTH_REJECT) {
		pr_err("Server rejected the authentication (TSRV_PKT_AUTH_REJECT)");
		pr_warn("Could be wrong username or password");
		return -EBADMSG;
	}

	if (srv_pkt->type != TSRV_PKT_AUTH_OK) {
		pr_err("Server sends unexpected packet for auth response (%hhu)",
		       srv_pkt->type);
		return -EBADMSG;
	}

	if (len < (PKT_MIN_LEN + expected_len)) {
		pr_err("Invalid auth response packet length (expected_len = %zu;"
		       " actual = %zu)", PKT_MIN_LEN + expected_len, len);
		return -EBADMSG;
	}

	srv_pkt->len = ntohs(srv_pkt->len);
	if ((size_t)srv_pkt->len != expected_len) {
		pr_err("Invalid auth response packet length (expected_len = %zu;"
		       " srv_pkt->len = %hu)", expected_len, srv_pkt->len);
		return -EBADMSG;
	}

	prl_notice(2, "Authentication success (got TSRV_PKT_AUTH_OK)!");
	return 0;
}


static int bring_up_iface(struct cli_udp_state *state)
{
	struct srv_pkt *srv_pkt = &state->pkt->srv;
	struct if_info *iff = &srv_pkt->auth_res.iff;
	struct if_info *iff2 = &state->cfg->iface.iff;
	const char *dev = state->cfg->iface.dev;

	strncpy2(iff->dev, dev, sizeof(iff->dev));
	*iff2 = *iff;

	if (state->cfg->iface.override_default)
		strncpy2(iff2->ipv4_pub, state->cfg->sock.server_addr,
			 sizeof(iff2->ipv4_pub));

	if (unlikely(!teavpn_iface_up(iff2))) {
		pr_err("teavpn_iface_up(): cannot bring up network interface");
		return -ENETDOWN;
	}
	state->need_remove_iff = true;
	return 0;
}


static int wait_for_auth_response(struct cli_udp_state *state)
{
	int ret;
	ssize_t recv_ret;
	int udp_fd = state->udp_fd;
	struct srv_pkt *srv_pkt = &state->pkt->srv;

	prl_notice(2, "Waiting for server auth response...");
	ret = poll_fd_input(state, udp_fd, 5000);
	if (unlikely(ret < 0))
		return ret;

	recv_ret = simple_do_recv_from(udp_fd, srv_pkt, PKT_MAX_LEN);
	if (unlikely(recv_ret < 0))
		return (int)recv_ret;

	ret = server_auth_res_chk(srv_pkt, (size_t)recv_ret);
	if (!ret) {
		prl_notice(2, "Authenticated as \"%s\"",
			   state->cfg->auth.username);
		ret = bring_up_iface(state);
	}

	return ret;
}


static int _do_auth(struct cli_udp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &state->pkt->cli;
	struct cli_cfg_auth *auth_c = &state->cfg->auth;

	prl_notice(2, "Authenticating as %s...", auth_c->username);
	send_len = cli_pprep_auth(cli_pkt, auth_c->username, auth_c->password);
	send_ret = simple_do_send_to(state->udp_fd, cli_pkt, send_len);
	return (send_ret >= 0) ? 0 : (int)send_ret;
}


static int do_auth(struct cli_udp_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try = 5;

try_again:
	ret = _do_auth(state);
	if (unlikely(ret))
		return ret;

	ret = wait_for_auth_response(state);
	if (ret == -ETIMEDOUT && try_count++ < max_try)
		goto try_again;

	return ret;
}


static int run_client_event_loop(struct cli_udp_state *state)
{
	switch (state->evt_loop) {
	case EVTL_EPOLL:
		return teavpn2_udp_client_epoll(state);
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
	uint8_t i, nn = state->cfg->sys.thread_num;
	int *tun_fds = state->tun_fds;

	if (!tun_fds)
		return;

	for (i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fds[i]);
	}
	al64_free(tun_fds);
}


static void close_udp_fd(struct cli_udp_state *state)
{
	if (state->udp_fd != -1) {
		prl_notice(2, "Closing udp_fd (fd=%d)...", state->udp_fd);
		close(state->udp_fd);
		state->udp_fd = -1;
	}
}


static void destroy_state(struct cli_udp_state *state)
{
	if (state->need_remove_iff) {
		prl_notice(2, "Removing virtual network interface configuration...");
		teavpn_iface_down(&state->cfg->iface.iff);
	}

	if (state->threads_wont_exit)
		return;

	close_tun_fds(state);
	close_udp_fd(state);
	al4096_free_munmap(state->pkt, sizeof(*state->pkt));
	al64_free(state);
}


int teavpn2_client_udp_run(struct cli_cfg *cfg)
{
	int ret = 0;
	struct cli_udp_state *state;

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
	ret = do_handshake(state);
	if (unlikely(ret))
		goto out;
	ret = do_auth(state);
	if (unlikely(ret))
		goto out;
	ret = run_client_event_loop(state);
out:
	if (unlikely(ret))
		pr_err("teavpn2_client_udp_run(): " PRERF, PREAR(-ret));

	if (state->udp_fd != -1)
		send_close_packet(state);

	destroy_state(state);
	return ret;
}

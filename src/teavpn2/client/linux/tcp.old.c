// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/client/linux/tcp.c
 *
 *  TCP handler for TeaVPN2 client
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/client/tcp.h>
#include <teavpn2/net/tcp_pkt.h>

#define MAX_ERR_C	(0xfu)
#define EPOLL_IN_EVT	(EPOLLIN | EPOLLPRI)


typedef enum _evt_cli_goto {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_srv_goto_t;


struct cli_tcp_state {
	pid_t			pid;		/* Main process PID           */
	int			epl_fd;		/* Epoll fd                   */
	int			net_fd;		/* Main TCP socket fd         */
	int			tun_fd;		/* TUN/TAP fd                 */
	bool			is_auth;	/* Is authenticated?          */
	bool			stop;		/* Stop the event loop?       */
	bool			reconn;		/* Reconnect if conn dropped? */
	uint8_t			reconn_c;	/* Reconnect count            */
	uint8_t			err_c;		/* Error count                */
	struct_pad(0, 3);
	struct cli_cfg		*cfg;		/* Config                     */
	uint32_t		send_c;		/* Number of send()           */
	uint32_t		recv_c;		/* Number of recv()           */
	size_t			recv_s;		/* Active bytes in recv_buf   */
	utsrv_pkt_t		recv_buf;	/* Server packet from recv()  */
	utcli_pkt_t		send_buf;	/* Client packet to send()    */
};


static struct cli_tcp_state *g_state;


static void interrupt_handler(int sig)
{
	struct cli_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int init_state(struct cli_tcp_state *state)
{
	state->pid      = getpid();
	state->epl_fd   = -1;
	state->net_fd   = -1;
	state->tun_fd   = -1;
	state->stop     = false;
	state->reconn   = true;
	state->reconn_c = 0;
	state->send_c   = 0;
	state->recv_c   = 0;
	state->recv_s   = 0;
	state->is_auth  = false;

	prl_notice(0, "My PID is %d", state->pid);

	return 0;
}


static int init_iface(struct cli_tcp_state *state)
{
	int fd;
	struct cli_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);
	fd = tun_alloc(j->dev, IFF_TUN);
	if (fd < 0)
		return -1;
	if (fd_set_nonblock(fd) < 0)
		goto out_err;

	state->tun_fd = fd;
	return 0;
out_err:
	close(fd);
	return -1;
}


static int socket_setup(int fd, struct cli_cfg *cfg)
{
	int rv;
	int err;
	int y;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 0;
	rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 30000;
	rv = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	/*
	 * TODO: Utilize `cfg` to set some socket options from config
	 */
	(void)cfg;
	return rv;

out_err:
	err = errno;
	pr_error("setsockopt(): " PRERF, PREAR(err));
	return rv;
}


static int init_socket(struct cli_tcp_state *state)
{
	int fd;
	int err;
	int retval;
	struct sockaddr_in addr;
	struct cli_sock_cfg *sock = &state->cfg->sock;
	char *server_addr = sock->server_addr;
	uint16_t server_port = sock->server_port;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	prl_notice(0, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		err = errno;
		retval = -err;
		pr_error("socket(): " PRERF, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (unlikely(retval < 0))
		goto out_err;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	if (!inet_pton(AF_INET, server_addr, &addr.sin_addr)) {
		err = EINVAL;
		retval = -err;
		pr_error("inet_pton(%s): " PRERF, server_addr, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Connecting to %s:%d...", server_addr, server_port);
again:
	retval = connect(fd, &addr, addrlen);
	if (retval < 0) {
		err = errno;
		if ((err == EINPROGRESS) || (err == EALREADY)) {
			usleep(1000);
			goto again;
		}

		retval = -err;
		pr_error("connect(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->net_fd = fd;
	prl_notice(0, "Connection established!");
	return 0;

out_err:
	if (fd > 0)
		close(fd);
	return retval;
}


static int epoll_add(int epl_fd, int fd, uint32_t events)
{
	int err;
	struct epoll_event event;

	/* Shut the valgrind up! */
	memset(&event, 0, sizeof(struct epoll_event));

	event.events = events;
	event.data.fd = fd;
	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_ADD, fd, &event) < 0)) {
		err = errno;
		pr_err("epoll_ctl(EPOLL_CTL_ADD): " PRERF, PREAR(err));
		return -1;
	}
	return 0;
}


static int epoll_delete(int epl_fd, int fd)
{
	int err;

	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_DEL, fd, NULL) < 0)) {
		err = errno;
		pr_error("epoll_ctl(EPOLL_CTL_DEL): " PRERF, PREAR(err));
		return -1;
	}
	return 0;
}


static int init_epoll(struct cli_tcp_state *state)
{
	int err;
	int ret;
	int epl_fd = -1;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create(3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	ret = epoll_add(epl_fd, tun_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	ret = epoll_add(epl_fd, net_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epl_fd = epl_fd;
	return 0;

out_create_err:
	err = errno;
	pr_err("epoll_create(): " PRERF, PREAR(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return -1;
}


static ssize_t send_to_server(struct cli_tcp_state *state, tcli_pkt_t *cli_pkt,
			      size_t len)
{
	int err;
	int net_fd = state->net_fd;
	ssize_t send_ret;

	state->send_c++;

	send_ret = send(net_fd, cli_pkt, len, 0);
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/*
			 * TODO: Handle pending buffer
			 *
			 * For now, let it fallthrough to error.
			 */
		}

		pr_err("send(fd=%d)" PRERF, net_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %ld bytes to server",
		   state->send_c, net_fd, send_ret);

	return send_ret;
}


static int send_hello(struct cli_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	tcli_pkt_t *cli_pkt;
	struct tcli_hello_pkt *hlo_pkt;

	prl_notice(2, "Sending hello packet to server...");

	cli_pkt = state->send_buf.__pkt_chk;
	hlo_pkt = &cli_pkt->hello_pkt;

	/*
	 * Tell the server what my version is.
	 */
	memset(&hlo_pkt->v, 0, sizeof(hlo_pkt->v));
	hlo_pkt->v.ver       = VERSION;
	hlo_pkt->v.patch_lvl = PATCHLEVEL;
	hlo_pkt->v.sub_lvl   = SUBLEVEL;
	strncpy(hlo_pkt->v.extra, EXTRAVERSION, sizeof(hlo_pkt->v.extra) - 1);
	hlo_pkt->v.extra[sizeof(hlo_pkt->v.extra) - 1] = '\0';

	data_len        = sizeof(struct tcli_hello_pkt);
	cli_pkt->type   = TCLI_PKT_HELLO;
	cli_pkt->npad   = 0;
	cli_pkt->length = htons(data_len);
	send_len        = TCLI_PKT_MIN_L + data_len;

	return (send_to_server(state, cli_pkt, send_len) > 0) ? 0 : -1;
}


static ssize_t send_auth(struct cli_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	tcli_pkt_t *cli_pkt;
	struct tcli_auth_pkt *auth_pkt;
	struct cli_auth_cfg *auc = &state->cfg->auth;

	cli_pkt  = state->send_buf.__pkt_chk;
	auth_pkt = &cli_pkt->auth_pkt;

	strncpy(auth_pkt->uname, auc->username, sizeof(auth_pkt->uname) - 1);
	strncpy(auth_pkt->pass, auc->password, sizeof(auth_pkt->pass) - 1);

	auth_pkt->uname[sizeof(auth_pkt->uname) - 1] = '\0';
	auth_pkt->pass[sizeof(auth_pkt->pass) - 1] = '\0';

	prl_notice(0, "Authenticating as %s", auth_pkt->uname);
	
	data_len        = sizeof(struct tcli_auth_pkt);
	cli_pkt->type   = TCLI_PKT_AUTH;
	cli_pkt->npad   = 0;
	cli_pkt->length = htons(data_len);
	send_len        = TCLI_PKT_MIN_L + data_len;

	return send_to_server(state, cli_pkt, send_len);
}


static evt_srv_goto_t handle_welcome(struct cli_tcp_state *state)
{
	/*
	 * TODO: Strict checking here.
	 */

	return send_auth(state) > 0 ? RETURN_OK : OUT_CONN_CLOSE;
}


static evt_srv_goto_t handle_server_pkt(tsrv_pkt_t *srv_pkt, uint16_t data_len,
				     	struct cli_tcp_state *state)
{
	(void)srv_pkt;
	(void)data_len;
	(void)state;

	evt_srv_goto_t retval = RETURN_OK;

	switch (srv_pkt->type) {
	case TSRV_PKT_WELCOME:
		/*
		 * Server will send us `welcome packet` if the
		 * version is supported by the TeaVPN2 server.
		 *
		 * See also: send_hello()
		 */
		retval = handle_welcome(state);
		goto out;
	case TSRV_PKT_AUTH_OK:
		/*
		 * Authentication success!
		 *
		 * We must have private IP information from
		 * this **AUTH OK** packet.
		 */
		// retval = handle_auth_ok();
		goto out;
	case TSRV_PKT_AUTH_REJECT:
		goto out;
	case TSRV_PKT_IFACE_DATA:
		goto out;
	case TSRV_PKT_REQSYNC:
		goto out;
	case TSRV_PKT_PING:
		goto out;
	case TSRV_PKT_CLOSE:
		goto out;
	}

	/*
	 * I don't put default on switch statement to shut
	 * the clang warning up!
	 */

	/* default: */
	/*
	 * TODO: Change the state to CT_NOSYNC and
	 *       create a recovery rountine.
	 */

	if ((NOTICE_MAX_LEVEL) >= 5) {
		/*
		 * Something is wrong!
		 *
		 * Let's debug this by hand by seeing the
		 * hexdump result.
		 */
		VT_HEXDUMP(srv_pkt, sizeof(*srv_pkt));
		panic("CORRUPTED PACKET!");
	}

	prl_notice(0, "Received invalid packet type from server (type: %d)",
		   srv_pkt->type);

	if (likely(!state->is_auth))
		return OUT_CONN_CLOSE;

	return OUT_CONN_ERR;
out:
	return retval;
}


static evt_srv_goto_t process_server_buf(size_t recv_s,
					 struct cli_tcp_state *state)
{
	uint16_t npad;
	uint16_t data_len;
	uint16_t fdata_len; /* Full data length                        */
	uint16_t cdata_len; /* Current received data length + plus pad */
	evt_srv_goto_t retval;

	tsrv_pkt_t *srv_pkt = state->recv_buf.__pkt_chk;
	char *recv_buf = srv_pkt->raw_data;

again:
	if (unlikely(recv_s < TSRV_PKT_MIN_L)) {
		/*
		 * We can't continue to process the packet at this point,
		 * because we have not received the `type of packet` and
		 * the `length of packet`.
		 *
		 * Kick out!
		 * Let's wait for the next cycle.
		 */
		goto out;
	}

	npad      = srv_pkt->npad;
	data_len  = ntohs(srv_pkt->length);
	fdata_len = data_len + npad;
	if (unlikely(data_len > TSRV_PKT_MAX_L)) {
		/*
		 * `data_len` must **never be greater** than TSRV_PKT_MAX_L.
		 *
		 * If we reach this block, then it must be corrupted packet!
		 *
		 * BTW, there are several possibilities here:
		 * - Server has been compromised to intentionally send broken
		 *   packet (it's very unlikely, uh...).
		 * - Packet has been corrupted when it was on the way (maybe
		 *   ISP problem?).
		 * - Bug on something we haven't yet known.
		 */
		prl_notice(0, "Server sends invalid packet length "
			      "(max_allowed_len = %zu; srv_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", TSRV_PKT_MAX_L,
			      data_len, recv_s);

		return state->is_auth ? OUT_CONN_ERR : OUT_CONN_CLOSE;
	}


	/* Calculate current received data length */
	cdata_len = (uint16_t)recv_s - (uint16_t)TSRV_PKT_MIN_L;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * **We really have received** the type and length of packet.
		 *
		 * However, the packet has not been fully received.
		 * So let's wait for the next cycle to process it.
		 */
		goto out;
	}

	retval = handle_server_pkt(srv_pkt, data_len, state);
	if (unlikely(retval != RETURN_OK))
		return retval;

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra packet on the tail, must memmove to
		 * the head before we run out of buffer.
		 */
		size_t cur_valid_size = TCLI_PKT_MIN_L + fdata_len;
		recv_s -= cur_valid_size;

		memmove(recv_buf, recv_buf + cur_valid_size, recv_s);

		prl_notice(5, "memmove (copy_size: %zu; recv_s: %zu; "
			      "cur_valid_size: %zu)", recv_s, recv_s,
			      cur_valid_size);

		goto again;
	}

	recv_s = 0;
out:
	state->recv_s = recv_s;
	return RETURN_OK;
}


static void handle_recv_server(int net_fd, struct cli_tcp_state *state)
{
	int err;
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	ssize_t recv_ret;

	recv_s   = state->recv_s;
	recv_len = TCLI_PKT_RECV_L - recv_s;
	recv_buf = state->recv_buf.raw_buf;
	recv_ret = recv(net_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_err("recv(fd=%d): " PRERF, net_fd, PREAR(err));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "Server has closed its connection");
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "recv(fd=%d) %ld bytes from server (recv_s = %zu)",
		   net_fd, recv_ret, recv_s);

	switch (process_server_buf(recv_s, state)) {
	case RETURN_OK:
		return;
	case OUT_CONN_ERR:
		goto out_err_c;
	case OUT_CONN_CLOSE:
		goto out_close_conn;
	}

	return;

out_err_c:
	state->recv_s = 0;

	if (state->err_c++ < MAX_ERR_C)
		return;

	prl_notice(0, "Reached the max number of error, closing...");

out_close_conn:
	epoll_delete(state->epl_fd, net_fd);
	state->stop = true;
	prl_notice(0, "Stopping event loop...");
}


static int handle_event(struct cli_tcp_state *state, struct epoll_event *event)
{
	int fd;
	bool is_err;
	uint32_t revents;
	const uint32_t errev = EPOLLERR | EPOLLHUP;

	fd      = event->data.fd;
	revents = event->events;
	is_err  = ((revents & errev) != 0);

	if (fd == state->net_fd) {
		if (unlikely(is_err)) {
			pr_err("tun_fd wait error");
			return -1;
		}
		handle_recv_server(fd, state);
	} else
	if (fd == state->tun_fd) {
		
	}

	return 0;
}


static int event_loop(struct cli_tcp_state *state)
{
	int err;
	int retval = 0;
	int maxevents = 32;

	int epl_ret;
	int epl_fd = state->epl_fd;
	struct epoll_event events[2];


	while (likely(!state->stop)) {
		epl_ret = epoll_wait(epl_fd, events, maxevents, 3000);
		if (unlikely(epl_ret == 0)) {
			/*
			 * epoll reached timeout.
			 *
			 * TODO: Do something meaningful here...
			 * Maybe keep alive ping to clients?
			 */
			continue;
		}


		if (unlikely(epl_ret < 0)) {
			err = errno;
			if (err == EINTR) {
				retval = 0;
				prl_notice(0, "Interrupted!");
				continue;
			}

			retval = -err;
			pr_error("epoll_wait(): " PRERF, PREAR(err));
			break;
		}

		for (int i = 0; likely(i < epl_ret); i++) {
			retval = handle_event(state, &events[i]);
			if (unlikely(retval < 0))
				goto out;
		}
	}

out:
	return retval;
}


static void destroy_state(struct cli_tcp_state *state)
{
	int epl_fd = state->epl_fd;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(net_fd != -1)) {
		prl_notice(0, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	if (likely(epl_fd != -1)) {
		prl_notice(0, "Closing state->epl_fd (%d)", epl_fd);
		close(epl_fd);
	}
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval = 0;
	struct cli_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct cli_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, interrupt_handler);
	signal(SIGINT, interrupt_handler);
	signal(SIGPIPE, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGQUIT, interrupt_handler);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (retval < 0)
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_epoll(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = send_hello(&state);
	if (unlikely(retval < 0))
		goto out;
	prl_notice(0, "Waiting for server welcome...");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

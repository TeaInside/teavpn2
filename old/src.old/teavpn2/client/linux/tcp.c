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
#include <inttypes.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/cpu.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/client/tcp.h>
#include <teavpn2/net/tcp_pkt.h>

#define MAX_ERR_C	(0xfu)

#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)

typedef enum _gt_srv_evt_t {
	HSE_OK = 0,
	HSE_ERR = 1,
	HSE_CLOSE = 2
} gt_srv_evt_t;


struct cli_tcp_state {
	int			epoll_fd;
	int			tcp_fd;
	int			tun_fd;

	bool			stop;
	bool			is_auth;
	uint8_t			err_c;
	struct_pad(0, 1);
	struct cli_cfg		*cfg;

	uint32_t		recv_c;
	uint32_t		send_c;
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	size_t			recv_s;

	utcli_pkt_t		send_buf;
	utsrv_pkt_t		recv_buf;
	struct iface_cfg	ciff;
	bool			need_iface_down;
	bool			aff_ok;
	struct_pad(1, 4);
	cpu_set_t		aff;
};


static struct cli_tcp_state *g_state;


static void handle_interrupt(int sig)
{
	struct cli_tcp_state *state = g_state;
	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int init_state(struct cli_tcp_state *state)
{
	struct cpu_ret_info cri;

	if (optimize_cpu_affinity(1, &cri) == 0) {
		memcpy(&state->aff, &cri.affinity, sizeof(state->aff));
		state->aff_ok = true;
	} else {
		CPU_ZERO(&state->aff);
		state->aff_ok = false;
	}

	optimize_process_priority(-20, &cri);

	state->epoll_fd     = -1;
	state->tcp_fd       = -1;
	state->tun_fd       = -1;
	state->stop         = false;
	state->err_c        = 0;
	state->send_c       = 0;
	state->recv_c       = 0;
	state->read_tun_c   = 0;
	state->write_tun_c  = 0;
	state->need_iface_down = false;

	return 0;
}


static int init_iface(struct cli_tcp_state *state)
{
	int fd;
	struct cli_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	fd = tun_alloc(j->dev, IFF_TUN | IFF_NO_PI);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	state->tun_fd = fd;
	return 0;
out_err:
	close(fd);
	return -1;
}


static int socket_setup(int fd, struct cli_tcp_state *state)
{
	int rv;
	int err;
	int y;
	bool soi = false;
	socklen_t len = sizeof(y);
	struct cli_cfg *cfg = state->cfg;
	const void *pv = (const void *)&y;
	const char *lv, *on;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}

	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &state->aff)) {
			y = i;
			soi = true;
			break;
		}
	}

	if (soi) {
		prl_notice(4, "Pinning SO_INCOMING_CPU to CPU %d", y);
		rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
		if (unlikely(rv < 0)) {
			lv = "SOL_SOCKET";
			on = "SO_INCOMING_CPU";
			rv = 0;
			goto out_err;
		}
	}

	y = 6;
	rv = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SO_PRIORITY";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	rv = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}

	y = 50000;
	rv = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}

	/*
	 * TODO: Utilize `cfg` to set some socket options from config
	 */
	(void)cfg;
	return rv;
out_err:
	err = errno;
	pr_err("setsockopt(%s, %s): " PRERF, lv, on, PREAR(err));
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
	retval = socket_setup(fd, state);
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
	retval = connect(fd, (void *)&addr, addrlen);
	if (retval < 0) {
		err = errno;
		if ((err == EINPROGRESS) || (err == EALREADY)) {
			usleep(5000);

			if (likely(!state->stop))
				goto again;
		}

		retval = -err;
		pr_error("connect(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = fd;
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


static int init_epoll(struct cli_tcp_state *state)
{
	int err;
	int ret;
	int epl_fd = -1;
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create(3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	ret = epoll_add(epl_fd, tun_fd, EPL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	ret = epoll_add(epl_fd, tcp_fd, EPL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epoll_fd = epl_fd;
	return 0;

out_create_err:
	err = errno;
	pr_err("epoll_create(): " PRERF, PREAR(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return -1;
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


static ssize_t send_to_server(struct cli_tcp_state *state, tcli_pkt_t *cli_pkt,
			      size_t len)
{
	int err;
	size_t usend_ret;
	ssize_t send_ret;
	int tcp_fd = state->tcp_fd;

	len += cli_pkt->npad;

	state->send_c++;
	send_ret = send(tcp_fd, cli_pkt, len, 0);
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/*
			 * TODO: Handle pending buffer
			 *
			 * For now, let it fallthrough to error.
			 */
			pr_err("Pending buffer detected on send(): EAGAIN");
			return 0;
		}

		pr_err("send(fd=%d) " PRERF, tcp_fd, PREAR(err));
		return -1;
	}

	usend_ret = (size_t)send_ret;
	if (unlikely(len != usend_ret)) {
		/*
		 * TODO: Handle pending buffer
		 */
		pr_err("Pending buffer detected: "
		       "(expected len: %zu; usend_ret: %zu)",
		       len, usend_ret);
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %zd bytes to server",
		   state->send_c, tcp_fd, send_ret);

	return send_ret;
}


static size_t set_cli_pkt_buf(tcli_pkt_t *cli_pkt, tcli_pkt_type_t type,
			      uint16_t length)
{
	cli_pkt->type   = type;
	cli_pkt->npad   = 0;
	cli_pkt->length = htons(length);

	return TCLI_PKT_MIN_L + length;
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
	memset(&hlo_pkt->v, 0, sizeof(hlo_pkt->v));

	/*
	 * Tell the server what my version is.
	 */
	hlo_pkt->v.ver       = VERSION;
	hlo_pkt->v.patch_lvl = PATCHLEVEL;
	hlo_pkt->v.sub_lvl   = SUBLEVEL;
	sane_strncpy(hlo_pkt->v.extra, EXTRAVERSION, sizeof(hlo_pkt->v.extra));

	data_len = sizeof(struct tcli_hello_pkt);
	send_len = set_cli_pkt_buf(cli_pkt, TCLI_PKT_HELLO, data_len);

	if (send_to_server(state, cli_pkt, send_len) > 0)
		return 0;

	return -1;
}


static int exec_epoll_wait(int epoll_fd, struct epoll_event *events,
			   int maxevents, struct cli_tcp_state *state)
{
	int err;
	int retval;

	retval = epoll_wait(epoll_fd, events, maxevents, 50);
	if (unlikely(retval == 0)) {
		/*
		 * epoll_wait() reaches timeout
		 *
		 * TODO: Do something meaningful here.
		 */

		/*
		 * Always re-read memory when idle, at least keep it
		 * on L2d/L3d cache.
		 */
		memcmp_explicit(state, state, sizeof(*state));
		return 0;
	}

	if (unlikely(retval < 0)) {
		err = errno;
		if (err == EINTR) {
			retval = 0;
			prl_notice(0, "Interrupted!");
			return 0;
		}

		pr_err("epoll_wait(): " PRERF, PREAR(err));
		return -err;
	}

	return retval;
}


static ssize_t handle_iface_read(int tun_fd, struct cli_tcp_state *state)
{
	int err;
	size_t send_len;
	ssize_t read_ret;
	tcli_pkt_t *cli_pkt;
	uint8_t busy_read_count = 0;

read_again:
	state->read_tun_c++;

	cli_pkt  = state->send_buf.__pkt_chk;
	read_ret = read(tun_fd, cli_pkt->raw_data, 4096);
	if (unlikely(read_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return 0;
		pr_err("read(fd=%d) from tun_fd " PRERF, tun_fd, PREAR(err));
		return -1;
	}

	if (unlikely(read_ret == 0))
		return 0;

	prl_notice(5, "[%10" PRIu32 "] read(fd=%d) %zd bytes from tun_fd",
		   state->read_tun_c, tun_fd, read_ret);

	send_len = set_cli_pkt_buf(cli_pkt, TCLI_PKT_IFACE_DATA,
				   (uint16_t)read_ret);
	send_to_server(state, cli_pkt, send_len);

	if (likely(busy_read_count++ < 10))
		goto read_again;

	return read_ret;
}



static int handle_tun_event(int tun_fd, struct cli_tcp_state *state,
			    uint32_t revents)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -1;

	return (int)handle_iface_read(tun_fd, state);
}


static void panic_dump(void *ptr, size_t len)
{
	if ((NOTICE_MAX_LEVEL) >= 5) {
		panic("Data corrution detected!");
		VT_HEXDUMP(ptr, len);
		panic("Not syncing --");
	}
}


static void print_corruption_notice(struct cli_tcp_state *state)
{
	tsrv_pkt_t *srv_pkt = state->recv_buf.__pkt_chk;
	panic_dump(srv_pkt, sizeof(*srv_pkt));
}


static ssize_t send_auth(struct cli_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	tcli_pkt_t *cli_pkt;
	struct cli_cfg *cfg;
	struct cli_auth_cfg *auth_cfg;
	struct tcli_auth_pkt *auth_pkt;
	char *uname, *pass;

	cfg      = state->cfg;
	auth_cfg = &cfg->auth;
	uname    = auth_cfg->username;
	pass     = auth_cfg->password;

	prl_notice(2, "Authenticating as %s...", uname);

	cli_pkt  = state->send_buf.__pkt_chk;
	auth_pkt = &cli_pkt->auth_pkt;
	memset(auth_pkt, 0, sizeof(struct tcli_auth_pkt));

	sane_strncpy(auth_pkt->uname, uname, sizeof(auth_pkt->uname));
	sane_strncpy(auth_pkt->pass, pass, sizeof(auth_pkt->pass));

	data_len = sizeof(struct tcli_auth_pkt);
	send_len = set_cli_pkt_buf(cli_pkt, TCLI_PKT_AUTH, data_len);

	return send_to_server(state, cli_pkt, send_len);
}


static gt_srv_evt_t handle_srpkt_welcome(uint16_t data_len,
					 struct cli_tcp_state *state)
{
	if (unlikely(state->is_auth))
		return HSE_OK;

	/* Wrong data length */
	if (unlikely(data_len != 0)) {
		prl_notice(0, "Server sends invalid welcome data length "
			   "(expected: 0; got: %u)", data_len);
		return HSE_CLOSE;
	}

	prl_notice(0, "Got welcome signal from server");

	return (send_auth(state) > 0) ? HSE_OK : HSE_CLOSE;
}


static ssize_t send_iface_ack(struct cli_tcp_state *state)
{
	size_t send_len;
	tcli_pkt_t *cli_pkt = state->send_buf.__pkt_chk;

	send_len = set_cli_pkt_buf(cli_pkt, TCLI_PKT_IFACE_ACK, 0);
	return send_to_server(state, cli_pkt, send_len);
}


static gt_srv_evt_t handle_srpkt_auth_ok(tsrv_pkt_t *srv_pkt, uint16_t data_len,
					 struct cli_tcp_state *state)
{
	struct auth_ret	*aret = &srv_pkt->auth_ok.aret;
	struct iface_cfg *iff = &aret->iface;
	struct cli_iface_cfg *j = &state->cfg->iface;
	struct cli_sock_cfg *sock = &state->cfg->sock;
	bool override_default = state->cfg->iface.override_default;


	/* Wrong data length */
	if (unlikely(data_len != sizeof(struct auth_ret))) {
		prl_notice(0, "Server sends invalid 'auth ok' packet length "
			   "(expected: 0; got: %u)", data_len);
		return HSE_CLOSE;
	}

	sane_strncpy(iff->dev, j->dev, sizeof(iff->dev));

	iff->mtu = ntohs(iff->mtu);

	prl_notice(0, "Authentication success");

	if (!override_default) {
		iff->ipv4_pub[0] = '\0';
		iff->ipv4_dgateway[0] = '\0';
	} else {
		sane_strncpy(iff->ipv4_pub, sock->server_addr,
			     sizeof(iff->ipv4_pub));
	}

	memcpy(&state->ciff, iff, sizeof(*iff));

	if (unlikely(!teavpn_iface_up(iff))) {
		pr_err("Cannot raise virtual network interface up");
		return HSE_CLOSE;
	}

	state->need_iface_down = true;
	state->is_auth = true;

	return send_iface_ack(state) > 0 ? HSE_OK : HSE_CLOSE;
}


static ssize_t handle_iface_write(tsrv_pkt_t *srv_pkt,
				  uint16_t data_len,
				  struct cli_tcp_state *state)
{
	ssize_t write_ret;
	int tun_fd = state->tun_fd;

	state->write_tun_c++;

	write_ret = write(tun_fd, srv_pkt->raw_data, data_len);
	if (unlikely(write_ret < 0)) {
		int err = errno;
		if (err == EAGAIN) {
			/* TODO: Handle pending TUN/TAP buffer */
			pr_err("Pending buffer detected on write(): EAGAIN");
			return 0;
		}

		pr_err("write(fd=%d) to tun_fd" PRERF, tun_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] write(fd=%d) %zd bytes to tun_fd",
		   state->write_tun_c, tun_fd, write_ret);

	return write_ret;
}


static gt_srv_evt_t handle_srpkt_iface_data(tsrv_pkt_t *srv_pkt,
					    uint16_t data_len,
					    struct cli_tcp_state *state)
{
	ssize_t write_ret;

	if (unlikely(!state->is_auth)) {
		prl_notice(0, "Server sends iface data in non authenticated "
			   "state");
		return HSE_CLOSE;
	}

	write_ret = handle_iface_write(srv_pkt, data_len, state);
	return (write_ret > 0) ? HSE_OK : HSE_ERR;
}


static gt_srv_evt_t process_server_pkt(tsrv_pkt_t *srv_pkt, uint16_t data_len,
				       struct cli_tcp_state *state)
{
	tsrv_pkt_type_t pkt_type = srv_pkt->type;

	if (likely(pkt_type == TSRV_PKT_IFACE_DATA))
		return handle_srpkt_iface_data(srv_pkt, data_len, state);
	if (likely(pkt_type == TSRV_PKT_WELCOME))
		return handle_srpkt_welcome(data_len, state);
	if (likely(pkt_type == TSRV_PKT_AUTH_OK))
		return handle_srpkt_auth_ok(srv_pkt, data_len, state);
	if (likely(pkt_type == TSRV_PKT_AUTH_REJECT))
		return HSE_OK;
	if (likely(pkt_type == TSRV_PKT_REQSYNC))
		return HSE_OK;
	if (likely(pkt_type == TSRV_PKT_PING))
		return HSE_OK;
	if (likely(pkt_type == TSRV_PKT_CLOSE))
		return HSE_OK;

	print_corruption_notice(state);

	prl_notice(0, "Server sends invalid packet type (type: %d) "
		      "CORRUPTED PACKET?", pkt_type);

	return state->is_auth ? HSE_ERR : HSE_CLOSE;
}


static gt_srv_evt_t handle_client_event3(size_t recv_s,
					 struct cli_tcp_state *state)
{
	char *recv_buf;
	tsrv_pkt_t *srv_pkt;

	uint8_t  npad;
	uint16_t data_len;
	size_t   fdata_len; /* Expected full data length + plus pad    */
	size_t   cdata_len; /* Current received data length + plus pad */
	gt_srv_evt_t retval;

	recv_buf = state->recv_buf.raw_buf;
	srv_pkt  = state->recv_buf.__pkt_chk;

process_again:
	if (unlikely(recv_s < TCLI_PKT_MIN_L)) {
		/*
		 * At this point, the packet has not been fully received.
		 *
		 * We have to wait for more bytes to identify the type of
		 * packet and its length.
		 *
		 * Bail out!
		 */
		goto out;
	}

	npad      = srv_pkt->npad;
	data_len  = ntohs(srv_pkt->length);
	fdata_len = data_len + npad;
	if (unlikely(data_len > TCLI_PKT_MAX_L)) {

		print_corruption_notice(state);

		/*
		 * `data_len` must **never be greater** than TCLI_PKT_MAX_L.
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
			      "(max_allowed_len = %zu; cli_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", TCLI_PKT_MAX_L,
			      data_len, recv_s);

		return state->is_auth ? HSE_ERR : HSE_CLOSE;
	}


	/* Calculate current received data length */
	cdata_len = recv_s - TCLI_PKT_MIN_L;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * Data has not been fully received. Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}

	assert(cdata_len >= fdata_len);
	retval = process_server_pkt(srv_pkt, data_len, state);
	if (unlikely(retval != HSE_OK))
		return retval;

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra bytes on the tail, must memmove to the front
		 * before we run out of buffer.
		 */

		char *source_ptr;
		size_t processed_len;
		size_t unprocessed_len;

		processed_len   = TCLI_PKT_MIN_L + fdata_len;
		unprocessed_len = recv_s - processed_len;
		source_ptr      = &(recv_buf[processed_len]);
		recv_s          = unprocessed_len;
		memmove(recv_buf, source_ptr, unprocessed_len);

		prl_notice(5, "memmove (copy_size: %zu; processed_len: %zu)",
			      recv_s, processed_len);

		goto process_again;
	}

	recv_s = 0;
out:
	state->recv_s = recv_s;
	return HSE_OK;
}


static gt_srv_evt_t handle_server_event2(int tcp_fd,
					 struct cli_tcp_state *state)
{
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	ssize_t recv_ret;
	uint8_t busy_recv_count = 0;
	gt_srv_evt_t retval;

recv_again:
	recv_s   = state->recv_s;
	recv_buf = state->recv_buf.raw_buf;
	recv_len = TSRV_PKT_RECV_L - recv_s;

	state->recv_c++;

	recv_ret = recv(tcp_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		int err = errno;
		if (err == EAGAIN)
			return HSE_OK;

		pr_err("recv(fd=%d): " PRERF, tcp_fd, PREAR(err));

		return HSE_ERR;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "Server has closed its connection");
		return HSE_CLOSE;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "[%10" PRIu32 "] recv(fd=%d) %zd bytes from server"
		   " (recv_s = %zu)", state->recv_c, tcp_fd, recv_ret, recv_s);

	retval = handle_client_event3(recv_s, state);
	if (unlikely(retval != HSE_OK))
		return retval;

	if (likely(busy_recv_count++ < 10))
		goto recv_again;

	return HSE_OK;
}


static int handle_server_event(int tcp_fd, struct cli_tcp_state *state,
			       uint32_t revents)
{
	gt_srv_evt_t jump_to;
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask)) {
		prl_notice(0, "Server has closed its connection");
		goto out_close;
	}

	jump_to = handle_server_event2(tcp_fd, state);
	if (likely(jump_to == HSE_OK)) {
		goto out_ok;
	} else
	if (unlikely(jump_to == HSE_ERR)) {
		goto out_err;
	} else
	if (unlikely(jump_to == HSE_CLOSE)) {
		goto out_close;
	} else {
		__builtin_unreachable();
	}

out_ok:
	return 0;

out_err:
	state->recv_s = 0;
	prl_notice(5, "[%03u] Got error", state->err_c);

	if (unlikely(state->err_c++ >= MAX_ERR_C)) {
		pr_err("Reached the max number of errors");
		goto out_close;
	}

	/* Tolerate small error */
	return 0;

out_close:
	state->stop = true;
	epoll_delete(state->epoll_fd, tcp_fd);
	close(tcp_fd);
	prl_notice(0, "Closing connection...");
	return 0;
}


static int handle_event(struct cli_tcp_state *state, struct epoll_event *event)
{
	int fd;
	uint32_t revents;

	fd      = event->data.fd;
	revents = event->events;

	if (likely(fd == state->tun_fd)) {
		return handle_tun_event(fd, state, revents);
	}

	if (likely(fd == state->tcp_fd)) {
		return handle_server_event(fd, state, revents);
	}

	pr_err("handle_event got invalid file descriptor");
	assert(0);
	return -1;
}


static int handle_events(struct cli_tcp_state *state,
			 struct epoll_event *events,
			 int num_of_events)
{
	int retval;

	for (int i = 0; likely(i < num_of_events); i++) {
		retval = handle_event(state, &events[i]);
		if (unlikely(retval < 0))
			return -1;
	}

	return 0;
}


static int event_loop(struct cli_tcp_state *state)
{
	int retval = 0;
	int maxevents = 3;
	int epoll_fd = state->epoll_fd;
	struct epoll_event events[3];

	/* Shut the valgrind up! */
	memset(events, 0, sizeof(events));

	while (likely(!state->stop)) {
		retval = exec_epoll_wait(epoll_fd, events, maxevents, state);

		if (unlikely(retval == 0))
			continue;

		if (unlikely(retval < 0))
			goto out;

		retval = handle_events(state, events, retval);
		if (unlikely(retval < 0))
			goto out;
	}

out:
	return retval;
}


static void close_file_descriptors(struct cli_tcp_state *state)
{
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;
	int epoll_fd = state->epoll_fd;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(tcp_fd != -1)) {
		prl_notice(0, "Closing state->tcp_fd (%d)", tcp_fd);
		close(tcp_fd);
	}

	if (likely(epoll_fd != -1)) {
		prl_notice(0, "Closing state->epoll_fd (%d)", epoll_fd);
		close(epoll_fd);
	}
}


static void destroy_state(struct cli_tcp_state *state)
{
	if (state->need_iface_down) {
		prl_notice(0, "Cleaning network interface...");
		teavpn_iface_down(&state->ciff);
	}
	close_file_descriptors(state);
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval = 0;
	struct cli_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct cli_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, handle_interrupt);
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGQUIT, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
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
	prl_notice(0, "Waiting for welcome signal from server...");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

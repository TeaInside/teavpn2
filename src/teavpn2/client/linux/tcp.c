
#include <poll.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/tcp.h>
#include <teavpn2/server/linux/tcp.h>

#define MAX_ERR_C (10u)
static struct cli_tcp_state *g_state;

static void intr_handler(int sig)
{
	struct cli_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	(void)sig;
}


static void init_state(struct cli_tcp_state *state)
{
	state->net_fd = -1;
	state->tun_fd = -1;
	state->stop = false;
	state->is_auth = false;
}


static int init_iface(struct cli_tcp_state *state)
{
	int fd;
	struct cli_iface_cfg *j = &state->cfg->iface;

	prl_notice(3, "Creating virtual network interface: \"%s\"...", j->dev);
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
	int y = 1;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	(void)cfg;
	return rv;

out_err:
	pr_error("setsockopt(): %s", strerror(errno));
	return rv;
}


static int init_socket(struct cli_tcp_state *state)
{
	int fd;
	int ern;
	int retval;
	struct sockaddr_in srv_addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	struct cli_sock_cfg *sock = &state->cfg->sock;
	char *server_addr = sock->server_addr;
	uint16_t server_port = sock->server_port;

	prl_notice(3, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		ern = errno;
		retval = -ern;
		pr_error("socket(): %s", strerror(ern));
		goto out_err;
	}


	prl_notice(3, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (retval < 0)
		goto out_err;

	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(server_port);

	if (!inet_pton(AF_INET, server_addr, &srv_addr.sin_addr)) {
		ern = EINVAL;
		retval = -ern;
		pr_error("inet_pton(%s): %s", server_addr, strerror(ern));
		goto out_err;
	}


	prl_notice(0, "Connecting to %s:%d...", server_addr, server_port);
again:
	retval = connect(fd, &srv_addr, addrlen);
	if (retval < 0) {
		ern = errno;
		if (ern == EINPROGRESS || ern == EALREADY)
			goto again;
		retval = -ern;
		pr_error("connect(): %s", strerror(ern));
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


static ssize_t send_to_server(struct cli_tcp_state *state,
			      struct cli_tcp_pkt *cli_pkt,
			      size_t send_len)
{
	ssize_t send_ret;

	send_ret = send(state->net_fd, cli_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		pr_error("send(): %s", strerror(errno));
		return -1;
	}
	prl_notice(11, "send() %ld bytes to server", send_ret);

	return send_ret;
}


static bool send_hello(struct cli_tcp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_tcp_pkt *cli_pkt = &state->cli_pkt;

	cli_pkt->type = CLI_PKT_HELLO;
	cli_pkt->length = 0;

	send_len = offsetof(struct cli_tcp_pkt, raw_data);
	send_ret = send_to_server(state, cli_pkt, send_len);
	return send_ret > 0;
}


static bool handle_auth_ok(struct cli_tcp_state *state)
{
	struct cli_cfg *cfg = state->cfg;
	struct cli_iface_cfg *iface_cfg = &cfg->iface;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;
	struct srv_auth_ok *auth_ok = &srv_pkt->auth_ok;
	struct iface_cfg *iface = &auth_ok->iface;

	prl_notice(0, "Authentication success!");

	strncpy(iface->dev, iface_cfg->dev, sizeof(iface->dev) - 1);

	if (unlikely(!raise_up_interface(iface))) {
		pr_error("Cannot raise up virtual network interface");
		return false;
	}

	prl_notice(0, "Virtual network interface has been raised up");
	prl_notice(0, "Initialization Sequence Completed");
	return true;
}


static bool check_banner_version(struct cli_tcp_state *state,
				 uint16_t fdata_len)
{
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	if (fdata_len != sizeof(struct srv_banner)) {
		pr_error("Cannot verify server banner version "
			 "(fdata_len != sizeof(struct srv_banner))");
		return false;
	}

	if (	srv_pkt->banner.cur.ver 	== 0
	     && srv_pkt->banner.cur.sub_ver 	== 0
	     && srv_pkt->banner.cur.sub_sub_ver	== 1) {
		/*
		 * Only accept teavpn2 v0.0.1 at the moment.
		 */
		return true;
	}

	pr_error("Server is running unsupported version of teavpn2");
	return false;
}


static bool send_auth(struct cli_tcp_state *state)
{
	ssize_t send_ret;
	uint16_t send_len;
	uint16_t data_len;
	struct cli_tcp_pkt *cli_pkt = &state->cli_pkt;
	struct auth_pkt	*auth = &cli_pkt->auth;
	struct cli_auth_cfg *auth_cfg = &state->cfg->auth;

	prl_notice(0, "Authenticating...");
	data_len = sizeof(struct auth_pkt);
	cli_pkt->type = CLI_PKT_AUTH;
	cli_pkt->length = htons(data_len);

	strncpy(auth->username, auth_cfg->username, sizeof(auth->username) - 1);
	strncpy(auth->password, auth_cfg->password, sizeof(auth->password) - 1);
	auth->username[sizeof(auth->username) - 1] = '\0';
	auth->password[sizeof(auth->password) - 1] = '\0';

	send_len = offsetof(struct cli_tcp_pkt, raw_data) + data_len;
	send_ret = send_to_server(state, cli_pkt, send_len);
	return send_ret > 0;
}


static bool handle_iface_write(struct cli_tcp_state *state, uint16_t fdata_len)
{
	ssize_t write_ret;
	int tun_fd = state->tun_fd;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	write_ret = write(tun_fd, srv_pkt->raw_data, fdata_len);
	if (write_ret < 0) {
		pr_error("write(): %s", strerror(errno));
		return false;
	}
	prl_notice(11, "write() %ld bytes to tun_fd", write_ret);

	return true;
}


static bool handle_iface_read(int tun_fd, struct cli_tcp_state *state)
{
	int ern;
	size_t send_len;
	ssize_t read_ret;
	ssize_t send_ret;
	struct cli_tcp_pkt *cli_pkt = &state->cli_pkt;
	char *buf = cli_pkt->raw_data;

	read_ret = read(tun_fd, buf, 4096);
	if (read_ret < 0) {
		ern = errno;
		if (ern == EAGAIN)
			return true;

		state->stop = true;
		pr_error("read(tun_fd): %s", strerror(ern));
		return false;
	}

	prl_notice(11, "read() %ld bytes from tun_fd", read_ret);

	cli_pkt->type   = CLI_PKT_DATA;
	cli_pkt->length = htons((uint16_t)read_ret);

	send_len = CLI_PKT_MIN_RSIZ + (uint16_t)read_ret;
	send_ret = send_to_server(state, cli_pkt, send_len);

	return send_ret > 0;
}


static void handle_server_data(int net_fd, struct cli_tcp_state *state)
{
	int ern;
	size_t recv_s;
	size_t recv_len;
	ssize_t recv_ret;
	char *recv_buf;
	struct srv_tcp_pkt *srv_pkt;
	uint16_t fdata_len; /* Full data length */
	uint16_t cdata_len; /* Current received data length */


	recv_s    = state->recv_s;
	recv_buf  = state->recv_buf;
	srv_pkt   = &state->srv_pkt;

	recv_len  = SRV_PKT_RSIZE - recv_s;
	recv_ret  = recv(net_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		ern = errno;
		if (ern == EAGAIN)
			return;
		pr_error("recv(): %s", strerror(ern));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(6, "Server has closed the connection");
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(11, "recv() %ld bytes from server (recv_s = %zu)", recv_ret,
		   recv_s);

back_chk:
	if (unlikely(recv_s < SRV_PKT_MIN_RSIZ)) {
		/*
		 * We haven't received the type and length of packet.
		 * It very unlikely happens, maybe connection is too
		 * slow (?)
		 */
		goto out_save_recv_s;
	}

	fdata_len = htons(srv_pkt->length);
	if (unlikely(fdata_len > SRV_PKT_DATA_SIZ)) {
		/*
		 * fdata_length must never be greater than SRV_PKT_DATA_SIZ.
		 * Corrupted packet?
		 */
		prl_notice(1, "Server sends invalid packet length "
			      "(max_allowed_len = %zu; srv_pkt->length = %u;"
			      "recv_s = %zu) CORRUPTED PACKET?",
			      SRV_PKT_DATA_SIZ, fdata_len, recv_s);
		goto out_err_c;
	}

	/* Calculate current data length */
	cdata_len = recv_s - CLI_PKT_MIN_RSIZ;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We've received the type and length of packet.
		 *
		 * However, the packet has not been fully received.
		 * So let's wait for the next cycle to process it.
		 */
		goto out_save_recv_s;
	}

	

	switch (srv_pkt->type) {
	case SRV_PKT_BANNER: {
		if (unlikely(!check_banner_version(state, fdata_len)))
			goto out_close_conn;
		if (unlikely(!send_auth(state)))
			goto out_close_conn;
		break;
	}
	case SRV_PKT_AUTH_OK: {
		if (unlikely(!handle_auth_ok(state)))
			goto out_close_conn;
		break;
	}
	case SRV_PKT_AUTH_REJECT: {
		prl_notice(0, "Authentication rejected by server");
		goto out_close_conn;
	}
	case SRV_PKT_DATA: {
		if (unlikely(!handle_iface_write(state, fdata_len)))
			goto out_close_conn;
		break;
	}
	case SRV_PKT_CLOSE: {
		prl_notice(6, "Server has sent close packet");
		goto out_close_conn;
	}
	default:
		prl_notice(11, "Received invalid packet from server (type: %d)",
			   srv_pkt->type);
		goto out_err_c;
	}


	prl_notice(15, "cdata_len = %u; fdata_len = %u", cdata_len, fdata_len);

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra packet on the tail, must memmove to
		 * the head before we run out of buffer.
		 */

		size_t cur_valid_size = CLI_PKT_MIN_RSIZ + fdata_len;
		size_t copy_size      = recv_s - cur_valid_size;

		memmove(recv_buf, recv_buf + cur_valid_size, copy_size);
		recv_s = copy_size;

		prl_notice(15, "memmove (copy_size: %zu; recv_s: %zu; "
			       "cur_valid_size: %zu)", copy_size, recv_s,
			       cur_valid_size);

		goto back_chk;
	}

	recv_s = 0;

out_save_recv_s:
	state->recv_s = recv_s;
	return;

out_err_c:
	state->recv_s = 0;
	if (state->err_c++ >= MAX_ERR_C) {
		pr_error("Reached the max number of error");
		goto out_close_conn;
	}
	return;

out_close_conn:
	prl_notice(0, "Stopping event loop...");
	state->stop = true;
	return;
}


static int event_loop(struct cli_tcp_state *state)
{
	int rv;
	int ern;
	int timeout;
	nfds_t nfds;
	int retval = 0;
	struct pollfd fds[2];
	int net_fd = state->net_fd;
	int tun_fd = state->tun_fd;
	short curev; /* Current returned events */
	const short inev  = POLLIN | POLLPRI;	/* Input events    */
	const short errev = POLLERR | POLLHUP;	/* Error events    */
	const short retev = inev | errev;	/* Returned events */


	fds[0].fd = net_fd;
	fds[0].events = inev;

	fds[1].fd = tun_fd;
	fds[1].events = inev;

	nfds = 2;
	timeout = 5000;

	for (;;) {
		if (unlikely(state->stop))
			break;

		rv = poll(fds, nfds, timeout);

		if (unlikely(rv == 0)) {
			/*
			 * Poll reached timeout.
			 *
			 * TODO: Do something meaningful here...
			 */
			continue;
		}

		if (unlikely(rv < 0)) {
			ern = errno;
			if (ern == EINTR) {
				retval = 0;
				prl_notice(0, "Interrupted!");
				break;
			}

			retval = -ern;
			pr_error("poll(): %s", strerror(ern));
			break;
		}


		curev = fds[0].revents;
		if (likely((curev & retev) != 0)) {
			if (likely((curev & inev) != 0)) {
				handle_server_data(net_fd, state);
			} else {
				/* Error? */
				break;
			}
			rv--;
		}

		curev = fds[1].revents;
		if (likely((rv > 0) && ((curev & retev) != 0))) {
			if (likely((curev & inev) != 0)) {
				if (unlikely(!handle_iface_read(tun_fd, state)))
					break;
			} else {
				/* Error? */
				break;
			}
			rv--;
		}
	}

	return retval;
}


static void destroy_state(struct cli_tcp_state *state)
{
	int net_fd = state->net_fd;
	int tun_fd = state->tun_fd;

	if (tun_fd != -1) {
		prl_notice(6, "Closing tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (net_fd != -1) {
		prl_notice(6, "Closing net_fd (%d)", net_fd);
		close(net_fd);
	}
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval;
	struct cli_tcp_state state;

	state.cfg = cfg;
	g_state = &state;

	signal(SIGINT, intr_handler);
	signal(SIGHUP, intr_handler);
	signal(SIGTERM, intr_handler);
	signal(SIGQUIT, intr_handler);

	init_state(&state);

	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = send_hello(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

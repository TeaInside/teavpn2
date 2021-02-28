
#include <poll.h>
#include <stdio.h>
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
	state->stop = false;
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
		ern = errno;
		retval = -ern;
		pr_error("inet_pton(%s): %s", server_addr, strerror(ern));
		goto out_err;
	}


	prl_notice(0, "Connecting to %s:%d...", server_addr, server_port);
again:
	retval = connect(fd, &srv_addr, addrlen);
	if (retval < 0) {
		ern = errno;
		if (ern == EINPROGRESS)
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


static int send_hello(struct cli_tcp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	int net_fd = state->net_fd;
	struct cli_tcp_pkt *cli_pkt = &state->cli_pkt;

	cli_pkt->type = CLI_PKT_HELLO;
	cli_pkt->length = 0;

	send_len = offsetof(struct cli_tcp_pkt, raw_data);
	send_ret = send(net_fd, cli_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		pr_error("send(): %s", strerror(errno));
		return -1;
	}
	prl_notice(11, "send(): %ld bytes", send_ret);

	return 0;
}


static void handle_server_data(int net_fd, struct cli_tcp_state *state)
{
	int ern;
	size_t recv_s;
	size_t recv_len;
	ssize_t recv_ret;
	char *recv_buf;
	struct srv_tcp_pkt *srv_pkt;

	recv_buf = state->recv_buf;
	srv_pkt  = &state->srv_pkt;
	recv_s   = state->recv_s;

	recv_len = sizeof(struct srv_tcp_pkt) - recv_s;
	recv_ret = recv(net_fd, recv_buf, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		ern = errno;
		if (ern == EAGAIN)
			return;
		pr_error("recv(): %s", strerror(ern));
		goto out_err_c;
	}


out_err_c:
	state->err_c++;
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


	fds[0].fd = net_fd;
	fds[0].events = POLLIN;

	fds[1].fd = -tun_fd; /* OFF */
	fds[1].events = POLLIN;

	nfds = 2;
	timeout = 5000;

	while (true) {
		rv = poll(fds, nfds, timeout);

		if (unlikely(rv == 0)) {
			/* Poll reached timeout. */
			goto eol;
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


		if (likely((fds[0].revents & POLLIN) != 0)) {
			handle_server_data(net_fd, state);
			rv--;
		}


		if (likely((fds[1].revents & POLLIN) != 0)) {
			rv--;
		}

	eol:
		if (unlikely(state->stop))
			break;
	}


	return retval;
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
	if (retval < 0)
		goto out;
	retval = init_socket(&state);
	if (retval < 0)
		goto out;
	retval = send_hello(&state);
	if (retval < 0)
		goto out;
	retval = event_loop(&state);
out:
	return retval;
}
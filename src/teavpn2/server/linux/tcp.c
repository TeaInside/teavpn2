
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>
#include <teavpn2/client/linux/tcp.h>


#define MAX_ERR_C (10u)
static struct srv_tcp_state *g_state;


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	(void)sig;
}


static int32_t push_clst(struct srv_tcp_clstack *stack, uint16_t val)
{
	uint16_t sp = stack->sp;

	assert(sp > 0);
	stack->arr[--sp] = val;
	stack->sp = sp;
	return (int32_t)val;
}


static int32_t pop_clst(struct srv_tcp_clstack *stack)
{
	int32_t val;
	uint16_t sp = stack->sp;
	uint16_t max_sp = stack->max_sp;

	/* sp must never be higher than max_sp */
	assert(sp <= max_sp);

	if (sp == max_sp)
		return -1; /* There is nothing in the stack */

	val = (int32_t)stack->arr[sp];
	stack->sp = ++sp;
	return (int32_t)val;
}


static void init_client_slots(struct srv_tcp_client *clients, uint16_t i)
{
	while (i--) {
		memset(&clients[i], 0, sizeof(struct srv_tcp_client));
		clients[i].cli_fd = -1;
		clients[i].arr_idx = i;
	}
}


static int init_state(struct srv_tcp_state *state)
{
	int tmp;
	struct srv_cfg *cfg = state->cfg;
	uint16_t *stack_arr = NULL;
	uint16_t max_conn = cfg->sock.max_conn;
	struct srv_tcp_client *clients = NULL;
	struct srv_tcp_clstack *stack = &state->stack;


	clients = calloc(max_conn, sizeof(struct srv_tcp_client));
	if (unlikely(clients == NULL))
		goto out_err_calloc;

	stack_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(stack_arr == NULL))
		goto out_err_calloc;

	stack->sp = max_conn;
	stack->max_sp = max_conn;
	stack->arr = stack_arr;

	init_client_slots(clients, max_conn);

	while (max_conn--)
		push_clst(stack, max_conn);

	state->net_fd = -1;
	state->tun_fd = -1;
	state->pipe_fd[0] = -1;
	state->pipe_fd[1] = -1;
	state->stop = false;
	state->clients = clients;
	return 0;


out_err_calloc:
	tmp = errno;
	free(clients);
	pr_error("calloc: Cannot allocate memory: %s", strerror(tmp));
	return -ENOMEM;
}


static int init_pipe(struct srv_tcp_state *state)
{
	prl_notice(6, "Initializing pipe...");
	if (unlikely(pipe(state->pipe_fd) < 0)) {
		int tmp = errno;
		pr_error("pipe(): %s", strerror(tmp));
		return -tmp;
	}

	prl_notice(6, "Pipe has been successfully created!");
	prl_notice(6, "state->pipe_fd[0] = %d", state->pipe_fd[0]);
	prl_notice(6, "state->pipe_fd[1] = %d", state->pipe_fd[1]);

	return 0;
}


static void destroy_state(struct srv_tcp_state *state)
{
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;
	int *pipe_fd = state->pipe_fd;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct srv_tcp_client *client;
	struct srv_tcp_client *clients = state->clients;

	if (pipe_fd[0] != -1) {
		prl_notice(6, "Closing state->pipe_fd[0] (%d)", pipe_fd[0]);
		close(pipe_fd[0]);
	}

	if (pipe_fd[1] != -1) {
		prl_notice(6, "Closing state->pipe_fd[1] (%d)", pipe_fd[1]);
		close(pipe_fd[1]);
	}

	if (tun_fd != -1) {
		prl_notice(6, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (net_fd != -1) {
		prl_notice(6, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	while (max_conn--) {
		client = clients + max_conn;
		if (client->is_used) {
			prl_notice(6, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);
		}
	}

	free(clients);
	free(state->stack.arr);
}


static int init_iface(struct srv_tcp_state *state)
{
	int fd;
	struct iface_cfg i;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(3, "Creating virtual network interface: \"%s\"...",j->dev);
	fd = tun_alloc(j->dev, IFF_TUN);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	memset(&i, 0, sizeof(struct iface_cfg));
	strncpy(i.dev, j->dev, sizeof(i.dev) - 1);
	strncpy(i.ipv4, j->ipv4, sizeof(i.ipv4) - 1);
	strncpy(i.ipv4_netmask, j->ipv4_netmask, sizeof(i.ipv4_netmask) - 1);
	i.mtu = j->mtu;

	if (unlikely(!raise_up_interface(&i)))
		goto out_err;

	state->tun_fd = fd;
	return 0;

out_err:
	close(fd);
	return -1;
}


static int socket_setup(int fd, struct srv_cfg *cfg)
{
	int rv;
	int y = 1;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	(void)cfg;
	return rv;

out_err:
	pr_error("setsockopt(): %s", strerror(errno));
	return rv;
}


static int init_socket(struct srv_tcp_state *state)
{
	int fd;
	int ern;
	int retval;
	struct sockaddr_in srv_addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;
	int backlog = sock->backlog;
	char *bind_addr = sock->bind_addr;
	uint16_t bind_port = sock->bind_port;

	prl_notice(3, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		ern = errno;
		retval = -ern;
		pr_error("socket(): %s", strerror(ern));
		goto out_err;
	}

	prl_notice(3, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&srv_addr, 0, sizeof(struct sockaddr_in));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(bind_port);
	srv_addr.sin_addr.s_addr = inet_addr(bind_addr);

	retval = bind(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (unlikely(retval < 0)) {
		ern = errno;
		retval = -ern;
		pr_error("bind(): %s", strerror(ern));
		goto out_err;
	}

	retval = listen(fd, backlog);
	if (unlikely(retval < 0)) {
		ern = errno;
		retval = -ern;
		pr_error("listen(): %s", strerror(ern));
		goto out_err;
	}


	state->net_fd = fd;
	prl_notice(0, "Listening on %s:%d...", bind_addr, bind_port);
	return retval;

out_err:
	if (fd > 0)
		close(fd);
	return retval;
}


static void accept_conn(int net_fd, struct pollfd *clfds,
			struct srv_tcp_state *state)
{
	int rv;
	int ern;
	int32_t ridx;
	uint16_t idx;
	const char *chtmp;
	char src_ip[IPV4LEN];
	uint16_t sport;
	struct pollfd *cltkn;
	struct sockaddr_in claddr;
	struct srv_tcp_client *client;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(&claddr, 0, addrlen);

	rv = accept(net_fd, &claddr, &addrlen);
	if (unlikely(rv < 0)) {
		ern = errno;
		if (ern == EAGAIN)
			return;
		pr_error("accept(): %s", strerror(ern));
		return;
	}

	/* Get readable source IP address */
	chtmp = inet_ntop(AF_INET, &claddr.sin_addr, src_ip, IPV4LEN);
	if (unlikely(chtmp == NULL)) {
		int ern = errno;
		pr_error("inet_ntop(%u): %s", claddr.sin_addr.s_addr,
			 strerror(ern));
		goto out_close;
	}

	/* Get readable source port */
	sport = ntohs(claddr.sin_port);

	ridx = pop_clst(&state->stack);
	if (unlikely(ridx == -1)) {
		prl_notice(1, "Client slot is full, can't accept connection");
		prl_notice(1, "Dropping connection from %s:%d", chtmp, sport);
		goto out_close;
	}


	/* Welcome new connection :) */
	idx = (uint16_t)ridx;

	cltkn = &clfds[idx];
	cltkn->fd = rv;
	cltkn->events = POLLIN;

	client = &state->clients[idx];
	client->is_used = true;
	client->is_conn = true;
	client->is_auth = false;
	client->ht_mutx = false;
	client->ctstate = CT_NEW;
	client->cli_fd = rv;
	client->err_c = 0;
	client->recv_c = 0;
	client->recv_s = 0;

	strncpy(client->src_ip, src_ip, IPV4LEN);
	client->src_port = sport;
	memcpy(&client->src_data, &claddr, sizeof(struct sockaddr_in));

	assert(client->arr_idx == idx);
	prl_notice(1, "New connection from %s:%d", chtmp, sport);
	return;

out_close:
	close(rv);
	return;
}


static void clear_disconnect(struct srv_tcp_client *client)
{
	client->is_used = false;
	client->is_conn = false;
	client->is_auth = false;
	client->ht_mutx = false;
	client->ctstate = CT_DISCONNECTED;
	client->cli_fd = -1;
}


static int send_server_banner(struct srv_tcp_client *client,
			      struct srv_tcp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	char *src_ip = client->src_ip;
	uint16_t src_port = client->src_port;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	srv_pkt->type   = SRV_PKT_BANNER;
	srv_pkt->length = sizeof(struct srv_banner);
	
	srv_pkt->banner.cur.ver = 0;
	srv_pkt->banner.cur.sub_ver = 0;
	srv_pkt->banner.cur.sub_sub_ver = 1;

	srv_pkt->banner.min.ver = 0;
	srv_pkt->banner.min.sub_ver = 0;
	srv_pkt->banner.min.sub_sub_ver = 1;

	srv_pkt->banner.max.ver = 0;
	srv_pkt->banner.max.sub_ver = 0;
	srv_pkt->banner.max.sub_sub_ver = 1;

	send_len = SRV_PKT_MIN_RSIZ + sizeof(struct srv_banner);
	send_ret = send(client->cli_fd, srv_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		pr_error("send() to %s:%d: %s", src_ip, src_port,
			 strerror(errno));
		return -1;
	}
	prl_notice(11, "send() %ld bytes to %s:%d", send_ret, src_ip, src_port);

	return 0;
}


static void handle_client(struct pollfd *cl, struct srv_tcp_state *state,
			  uint16_t i)
{
	int ern;
	size_t recv_s;
	size_t recv_len;
	ssize_t recv_ret;
	char *recv_buf;
	struct cli_tcp_pkt *cli_pkt;
	struct srv_tcp_client *client;
	char *src_ip;
	uint16_t src_port;
	uint16_t fdata_len; /* Full data length    */
	uint16_t cdata_len; /* Current data length */

	client   = &state->clients[i];
	cli_pkt  = &client->cli_pkt;
	recv_s   = client->recv_s;
	recv_buf = client->recv_buf;
	src_ip   = client->src_ip;
	src_port = client->src_port;

	recv_len = sizeof(struct cli_tcp_pkt) - recv_s;
	recv_ret = recv(cl->fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		ern = errno;
		if (ern == EAGAIN)
			return;
		pr_error("recv(): %s", strerror(ern));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(6, "%s:%u has closed its connection", src_ip,
			   src_port);
		goto out_close_conn;
	}

	prl_notice(11, "recv() %ld bytes from %s:%d", recv_ret, src_ip,
		   src_port);


	recv_s += (size_t)recv_ret;
	if (unlikely(recv_s < CLI_PKT_MIN_RSIZ)) {
		/*
		 * We haven't received the type and length of packet.
		 * Very unlikely happens, maybe connection is too slow (?)
		 */
		goto out_save_recv_s;
	}

	fdata_len = htons(cli_pkt->length);
	if (unlikely(fdata_len > CLI_PKT_DATA_SIZ)) {
		/*
		 * Client sends invalid length.
		 *
		 * Possibilities in this case:
		 * - There is a bug in client module.
		 * - The packet has been corrupted.
		 * - Client has been compromised to send malicious packet.
		 * - Or whatever causes packet corruption (?)
		 */
		prl_notice(1, "Client sends invalid packet len (%s:%u) "
			   "(max_allowed_len = %zu; cli_pkt->length = %u;"
			   " recv_s = %zu) POSSIBLE BUG!", src_ip, src_port,
			   CLI_PKT_DATA_SIZ, fdata_len, recv_s);
		goto out_err_c;
	}

	/* Calculate current data length */
	cdata_len = recv_s - CLI_PKT_MIN_RSIZ;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We have received the type and length of packet, but
		 * incomplete, let's wait a bit longer in the next cycle.
		 */
		goto out_save_recv_s;
	}

	assert(cdata_len == fdata_len);

	switch (cli_pkt->type) {
	case CLI_PKT_HELLO:
		if (unlikely(send_server_banner(client, state) < 0))
			goto out_close_conn;
		break;
	case CLI_PKT_AUTH:
		break;
	case CLI_PKT_DATA:
		break;
	case CLI_PKT_CLOSE:
		break;
	default:
		prl_notice(11, "Received invalid packet from %s:%d (type: %d)",
			   src_ip, src_port, cli_pkt->type);

		if (likely(!client->is_auth))
			goto out_close_conn;
		break;
	}

	return;

out_save_recv_s:
	client->recv_s = recv_s;
	return;

out_err_c:
	client->recv_s = 0;
	if (unlikely(client->err_c++ >= MAX_ERR_C)) {
		prl_notice(3, "Connection %s:%d reached the max number of "
			   "error", src_ip, src_port);
		goto out_close_conn;
	}
	return;

out_close_conn:
	prl_notice(3, "Closing connection fd from %s:%d", src_ip, src_port);
	close(cl->fd);
	cl->fd = -1;
	clear_disconnect(client);
	return;
}


static int event_loop(struct srv_tcp_state *state)
{
	int rv;
	int ern;
	int timeout;
	int retval = 0;
	int net_fd = state->net_fd;
	int tun_fd = state->tun_fd;
	int *pipe_fd = state->pipe_fd;
	struct pollfd *fds;
	struct pollfd *clfds;
	uint16_t max_conn = state->cfg->sock.max_conn;

	fds = calloc(max_conn + 3, sizeof(struct pollfd));
	if (unlikely(fds == NULL)) {
		pr_error("calloc: Cannot allocate memory: %s", strerror(errno));
		return -ENOMEM;
	}

	fds[0].fd = net_fd;;
	fds[0].events = POLLIN;

	fds[1].fd = -tun_fd; /* OFF */
	fds[1].events = POLLIN;

	fds[2].fd = pipe_fd[0];
	fds[2].events = POLLIN;

	clfds = fds + 3;

	for (uint16_t i = 0; i < max_conn; i++)
		clfds[i].fd = -1;

	state->fds = fds;
	state->nfds = 3 + max_conn;
	timeout = 5000;

	while (true) {
		rv = poll(fds, state->nfds, timeout);

		prl_notice(15, "==== poll() = %d", rv);

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

		if (unlikely((fds[0].revents & POLLIN) != 0)) {
			accept_conn(net_fd, clfds, state);
			rv--;
		}

		if (likely((rv != 0) && ((fds[1].revents & POLLIN) != 0))) {
			rv--;
		}

		for (uint16_t i = 0; (i < max_conn) && (rv > 0); i++) {
			if ((clfds[i].revents & POLLIN) != 0) {
				handle_client(&clfds[i], state, i);
				rv--;
			}
		}

	eol:
		if (unlikely(state->stop))
			break;
	}

	free(fds);
	return retval;
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	memset(&state, 0, sizeof(state));

	state.cfg = cfg;
	g_state = &state;

	signal(SIGINT, intr_handler);
	signal(SIGHUP, intr_handler);
	signal(SIGTERM, intr_handler);
	signal(SIGQUIT, intr_handler);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_pipe(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/server/plat/linux/iface.h>

static struct srv_tcp_state *state_g = NULL;


static int32_t push_client_stack(struct srv_client_stack *stack, uint16_t i)
{
	uint16_t sp = stack->sp;

	assert(sp != 0);

	stack->block[--sp] = i;
	stack->sp = sp;

	return (int32_t)i;
}


static int32_t pop_client_stack(struct srv_client_stack *stack)
{
	int32_t ret;
	uint16_t sp = stack->sp;

	/* sp must never be higher than max_sp */
	assert(sp <= stack->max_sp);

	if (sp == stack->max_sp)
		return -1;

	ret = (int32_t)stack->block[sp];
	stack->sp = ++sp;
	return ret;
}


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = state_g;

	state->stop = true;
	putchar(10);
	(void)sig;
}


static int client_init(struct tcp_client *client)
{
	int tmp;

	client->is_used = false;
	client->is_connected = false;
	client->is_authorized = false;
	client->tun_fd = -1;
	client->cli_fd = -1;

	if (client->ht_mutex_active)
		pthread_mutex_destroy(&(client->ht_mutex));

	/* See: http://git.savannah.gnu.org/cgit/hurd/libpthread.git/tree/sysdeps/generic/pt-mutex-init.c */
	tmp = pthread_mutex_init(&(client->ht_mutex), NULL);
	if (tmp != 0) {
		int tmp_err;
		tmp_err = tmp > 0 ? tmp : -tmp;
		pr_error("pthread_mutex_init: %s", strerror(tmp_err));
		return -tmp_err;
	}

	client->ht_mutex_active = true;

	memset(client->username, 0, sizeof(client->username));
	memset(client->src_ip, 0, sizeof(client->src_ip));
	memset(client->send_buf, 0, sizeof(client->send_buf));
	memset(client->recv_buf, 0, sizeof(client->recv_buf));

	client->err_c = 0;
	client->send_s = 0;
	client->send_c = 0;
	client->recv_s = 0;
	client->recv_c = 0;

	return 0;
}


static int init_tcp_state(struct srv_tcp_state *state)
{
	int retval = 0;
	uint16_t *stack_block;
	struct tcp_client *clients;
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;
	uint16_t tmp_dec = max_conn;

	clients = calloc(max_conn, sizeof(*clients));
	if (clients == NULL) {
		pr_error("calloc: %s", strerror(errno));
		return -ENOMEM;
	}

	for (uint16_t i = 0; i < max_conn; i++) {
		retval = client_init(&clients[i]);
		if (retval != 0)
			goto out_err;
	}

	stack_block = calloc(max_conn, sizeof(*stack_block));
	if (stack_block == NULL) {
		pr_error("calloc: %s", strerror(errno));
		retval = -ENOMEM;
		goto out_err;
	}

	state->stack.sp = max_conn;
	state->stack.max_sp = max_conn;
	state->stack.block = stack_block;

	while (tmp_dec--)
		push_client_stack(&state->stack, tmp_dec);

	state->stop = false;
	state->n_online = 0;
	state->clients = clients;

	return retval;

out_err:
	free(clients);
	return retval;
}


inline static void client_close_fd(struct tcp_client *client, uint16_t i)
{
	int fd;

	fd = client->tun_fd;
	if (fd != -1) {
		prl_notice(3, "Closing clients[%d].tun_fd (%d)...", i, fd);
		close(fd);
	}

	fd = client->cli_fd;
	if (fd != -1) {
		pthread_mutex_lock(&client->ht_mutex);
		prl_notice(3, "Closing clients[%d].cli_fd (%d)...", i, fd);
		close(fd);
		pthread_mutex_unlock(&client->ht_mutex);
	}
}


static void destroy_tcp_state(struct srv_tcp_state *state)
{
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;
	struct tcp_client *clients = state->clients;

	for (uint16_t i = 0; i < max_conn; i++) {
		client_close_fd(&clients[i], i);

		if (clients[i].ht_mutex_active) {
			pthread_mutex_destroy(&clients[i].ht_mutex);
			clients[i].ht_mutex_active = false;
		}
	}


	free(clients);
	free(state->stack.block);

	if (state->net_fd != -1) {
		prl_notice(3, "Closing socket fd (%d)...", state->net_fd);
		close(state->net_fd);
	}
}


static int setup_socket_tcp_server(int fd)
{
	int rv;
	int y = 1;
	socklen_t len = sizeof(y);


	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&y, len);
	if (rv < 0)
		goto out_err;


	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&y, len);
	if (rv < 0)
		goto out_err;


	return 0;

out_err:
	pr_error("setsockopt(): %s", strerror(errno));
	return rv;
}


static int init_socket_tcp_server(struct srv_tcp_state *state)
{
	int fd;
	int retval = 0;
	struct sockaddr_in srv_addr;
	struct srv_sock_cfg *sock_cfg = &(state->cfg->sock);

	const char *bind_addr = sock_cfg->bind_addr;
	uint16_t bind_port = sock_cfg->bind_port;


	prl_notice(2, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		int tmp = errno;
		retval = -tmp;
		pr_error("socket(): %s", strerror(tmp));
		goto out_err;
	}


	prl_notice(2, "Setting up socket file descriptor...");
	retval = setup_socket_tcp_server(fd);
	if (retval < 0)
		goto out_err;


	memset(&srv_addr, 0, sizeof(struct sockaddr_in));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_port = htons(bind_port);
	srv_addr.sin_addr.s_addr = inet_addr(bind_addr);


	retval = bind(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (retval < 0) {
		int tmp = errno;
		retval = -tmp;
		pr_error("bind(): %s", strerror(tmp));
		goto out_err;
	}


	retval = listen(fd, sock_cfg->backlog);
	if (retval < 0) {
		int tmp = errno;
		retval = -tmp;
		pr_error("listen(): %s", strerror(tmp));
		goto out_err;
	}


	state->net_fd = fd;
	prl_notice(0, "Listening on %s:%d...", bind_addr, bind_port);

	return retval;

out_err:
	if (fd > 0) {
		prl_notice(3, "Closing socket descriptor (%d)...", fd);
		close(fd);
	}

	return retval;
}


static void tcp_accept_event(struct srv_tcp_state *state)
{
	int rv;
	int32_t n_index;
	int net_fd = state->net_fd;
	struct sockaddr_in cli_addr;
	char r_src_ip[IPV4LEN];
	uint16_t r_src_port;
	struct tcp_client *client;
	struct pollfd *clfds;
	socklen_t addrlen = sizeof(cli_addr);

	memset(&cli_addr, 0, sizeof(cli_addr));

	rv = accept(net_fd, &cli_addr, &addrlen);
	if (unlikely(rv < 0)) {
		int tmp = errno;
		if (tmp == EAGAIN)
			return;
		pr_error("accept(): %s", strerror(tmp));
		return;
	}


	if (inet_ntop(AF_INET, &cli_addr.sin_addr, r_src_ip, IPV4LEN) == NULL) {
		pr_error("tcp_accept_event: inet_ntop(%lx): %s",
			 cli_addr.sin_addr.s_addr, strerror(errno));
		goto out_close;
	}

	r_src_port = ntohs(cli_addr.sin_port);


	n_index = pop_client_stack(&state->stack);
	if (n_index == -1) {
		prl_notice(1, "Client slot is full, dropping connection from "
			   "%s:%d...", r_src_ip, r_src_port);
		goto out_close;
	}

	clfds = &state->fds[1];
	client = &state->clients[n_index];

	client->is_used = true;
	client->is_connected = true;
	client->is_authorized = false;

	client->cli_fd = rv;
	client->ev_state = EV_FIRST_CONNECT;

	client->src_ip = cli_addr;

	/* Save human readable IP and port */
	strncpy(client->r_src_ip, r_src_ip, sizeof(client->r_src_ip));
	client->r_src_port = r_src_port;

	/* Set fds for poll */
	clfds[n_index].fd = rv;
	clfds[n_index].events = POLLIN;

	/* +1 since nfds also contains main TCP socket fd */
	if (state->nfds < (state->cfg->sock.max_conn + 1u))
		state->nfds++;

	return;

out_close:
	close(rv);
}


static void handle_ev_first_connect(struct srv_tcp_state *state,
				    struct tcp_client *client)
{
	(void)state;
	(void)client;
}


static void handle_ev_authorization(struct srv_tcp_state *state,
				    struct tcp_client *client)
{
	(void)state;
	(void)client;
}


static void handle_ev_established(struct srv_tcp_state *state,
				  struct tcp_client *client)
{
	(void)state;
	(void)client;
}


static void handle_ev_disconnected(struct srv_tcp_state *state,
				   struct tcp_client *client)
{
	(void)state;
	(void)client;
}


static void handle_client_event(struct srv_tcp_state *state, uint16_t idx)
{
	struct tcp_client *client = &state->clients[idx];

	switch (client->ev_state) {
	case EV_FIRST_CONNECT:
		handle_ev_first_connect(state, client);
		break;

	case EV_AUTHORIZATION:
		handle_ev_authorization(state, client);
		break;

	case EV_ESTABLISHED:
		handle_ev_established(state, client);
		break;

	case EV_DISCONNECTED:
		handle_ev_disconnected(state, client);
		break;

	default:
		pr_error("Invalid state on handle_client_event: state = %d",
			 client->ev_state);
		abort();
		break;
	}
}


static int handle_tcp_event_loop(struct srv_tcp_state *state)
{
	int retval;
	int timeout;
	struct pollfd *fds = NULL;
	struct pollfd *clfds = NULL; /* fds slot for client */
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;


	retval = 0;

	fds = calloc(max_conn + 1, sizeof(*fds));
	if (fds == NULL) {
		pr_error("calloc(): %s", strerror(errno));
		return -ENOMEM;
	}

	timeout = 3000;
	state->fds = fds;
	state->nfds = 1;

	fds[0].fd = state->net_fd;
	fds[0].events = POLLIN;

	clfds = &fds[1];

	prl_notice(0, "Initialization Sequence Completed");

	while (true) {
		int rv;

		rv = poll(fds, state->nfds, timeout);

		if (unlikely(rv == 0)) {

			/* Poll reached timeout. */

			/*
			 * TODO: Rearrange fds and state->clients.
			 * (Deal with dead descriptors)
			 */
			goto end_of_loop;
		}


		if (unlikely(rv < 0)) {
			int tmp = errno;

			if (tmp == EINTR && state->stop) {
				retval = 0;
				prl_notice(0, "Interrupted, closing...");
				goto out;
			}

			retval = -tmp;
			pr_error("poll(): %s", strerror(tmp));
			goto out;
		}


		if (unlikely((fds[0].revents & POLLIN) != 0)) {
			tcp_accept_event(state);
			rv--;
		}


		for (uint16_t i = 0; likely((rv > 0) && (i < max_conn)); i++) {
			if (likely((clfds[i].revents & POLLIN) != 0))
				handle_client_event(state, i);
		}


	end_of_loop:
		if (state->stop)
			break;
	}


out:
	free(fds);
	state->fds = NULL;
	return retval;
}


int teavpn_tcp_server(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	memset(&state, 0, sizeof(state));

	state.cfg = cfg;
	state_g = &state; /* For interrupt signal */

	signal(SIGINT, intr_handler);
	signal(SIGHUP, intr_handler);
	signal(SIGQUIT, intr_handler);
	signal(SIGTERM, intr_handler);


	retval = init_tcp_state(&state);
	if (unlikely(retval != 0))
		goto out;


	retval = init_iface_tcp_server(&state);
	if (unlikely(retval != 0))
		goto out;


	retval = init_socket_tcp_server(&state);
	if (unlikely(retval != 0))
		goto out;


	retval = handle_tcp_event_loop(&state);
	if (unlikely(retval != 0))
		goto out;


out:
	destroy_tcp_state(&state);
	return retval;
}


#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/tcp.h>

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/server/plat/linux/iface.h>

static struct srv_tcp_state *state_g = NULL;


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = state_g;

	state->stop = true;

	putchar(10);
	(void)sig;
}


static int init_tcp_state(struct srv_tcp_state *state)
{
	int retval = 0;
	struct srv_cfg *cfg = state->cfg;
	struct tcp_client *clients;
	uint16_t max_conn = cfg->sock.max_conn;

	clients = calloc(max_conn, sizeof(*clients));
	if (clients == NULL) {
		pr_error("calloc: %s", strerror(errno));
		return -ENOMEM;
	}

	for (uint16_t i = 0; i < max_conn; i++) {
		int tmp;

		clients[i].tun_fd = -1;
		clients[i].cli_fd = -1;

		/* See: http://git.savannah.gnu.org/cgit/hurd/libpthread.git/tree/sysdeps/generic/pt-mutex-init.c */
		tmp = pthread_mutex_init(&(clients[i].ht_mutex), NULL);
		if (tmp != 0) {
			int tmp_err;
			tmp_err = tmp > 0 ? tmp : -tmp;
			retval  = -tmp_err;
			pr_error("pthread_mutex_init: %s", strerror(tmp_err));
			goto out_err;
		}
		clients[i].ht_mutex_active = true;
	}

	state->stop = false;
	state->n_online = 0;
	state->n_free_p = 0;
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
		pthread_mutex_lock(&(client->ht_mutex));
		prl_notice(3, "Closing clients[%d].cli_fd (%d)...", i, fd);
		close(fd);
		pthread_mutex_unlock(&(client->ht_mutex));
	}
}


static void destroy_tcp_state(struct srv_tcp_state *state)
{
	struct srv_cfg *cfg = state->cfg;
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = cfg->sock.max_conn;

	for (uint16_t i = 0; i < max_conn; i++) {
		client_close_fd(&clients[i], i);

		if (clients[i].ht_mutex_active) {
			pthread_mutex_destroy(&(clients[i].ht_mutex));
			clients[i].ht_mutex_active = false;
		}
	}


	free(clients);

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
		pr_error("socket(): %s", strerror(tmp));
		retval = -tmp;
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
		pr_error("bind(): %s", strerror(tmp));
		retval = -tmp;
		goto out_err;
	}


	retval = listen(fd, sock_cfg->backlog);
	if (retval < 0) {
		int tmp = errno;
		pr_error("listen(): %s", strerror(tmp));
		retval = -tmp;
		goto out_err;
	}


	prl_notice(0, "Listening on %s:%d...", bind_addr, bind_port);


	state->net_fd = fd;

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
	struct sockaddr_in cli_addr;
	int net_fd = state->net_fd;
	socklen_t addrlen = sizeof(cli_addr);

	memset(&cli_addr, 0, sizeof(cli_addr));

	rv = accept(net_fd, &cli_addr, &addrlen);
	if (unlikely(rv < 0)) {
		pr_error("accept(): %s", strerror(errno));
		return;
	}


}


__attribute__((noinline))
static int handle_tcp_event_loop(struct srv_tcp_state *state)
{
	int retval = 0;
	int timeout;
	nfds_t nfds;
	struct pollfd *fds = NULL;
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;


	fds = calloc(max_conn + 1, sizeof(*fds));
	if (fds == NULL) {
		pr_error("calloc(): %s", strerror(errno));
		return -ENOMEM;
	}

	nfds = 1;
	timeout = 15000;

	fds[0].fd = state->net_fd;
	fds[0].events = POLLIN;

	prl_notice(0, "Initialization Sequence Completed");

	while (true) {
		int rv;

		rv = poll(fds, nfds, timeout);

		if (unlikely(rv == 0)) {
			/* Timeout */
			continue;
		}

		if (unlikely(rv < 0)) {
			int tmp = errno;

			if ((tmp == EINTR) && state->stop) {
				retval = 0;
				prl_notice(0, "Interrupted, closing...");
				goto out;
			}

			pr_error("poll(): %s", strerror(tmp));
			retval = -tmp;
			goto out;
		}


		if (unlikely((fds[0].revents & POLLIN) != 0))
			tcp_accept_event(state);

	}


out:
	free(fds);
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

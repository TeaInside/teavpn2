
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/server/plat/linux/iface.h>


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
			retval = -tmp;
			goto out_err;
		}
	}


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
		prl_notice(3, "Closing clients[%d].cli_fd (%d)...", i, fd);
		close(fd);
	}
}


static void destroy_tcp_state(struct srv_tcp_state *state)
{
	struct srv_cfg *cfg = state->cfg;
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = cfg->sock.max_conn;

	for (uint16_t i = 0; i < max_conn; i++) {
		client_close_fd(&clients[i], i);
		pthread_mutex_destroy(&(clients[i].ht_mutex));
	}


	free(clients);
}


int teavpn_tcp_server(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	memset(&state, 0, sizeof(state));

	state.cfg = cfg;

	retval = init_tcp_state(&state);
	if (unlikely(retval < 0))
		goto out;


	retval = init_iface_tcp_server(&state);
	if (unlikely(retval < 0))
		goto out;

out:
	destroy_tcp_state(&state);
	return retval;
}

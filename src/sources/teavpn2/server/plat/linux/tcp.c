
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/server/plat/linux/iface.h>






static int init_tcp_state(struct srv_tcp_state *state)
{
	struct srv_cfg *cfg = state->cfg;
	struct tcp_client *clients;
	uint16_t max_conn = cfg->sock.max_conn;

	clients = calloc(max_conn, sizeof(*clients));
	if (clients == NULL) {
		pr_error("calloc: %s", strerror(errno));
		return -ENOMEM;
	}

	state->clients = clients;
	return 0;
}




int teavpn_tcp_server(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	state.cfg = cfg;


	retval = init_tcp_state(&state);
	if (retval < 0)
		goto out;


	retval = init_iface_tcp_server(&state);
	if (retval < 0)
		goto out;

out:
	return retval;
}

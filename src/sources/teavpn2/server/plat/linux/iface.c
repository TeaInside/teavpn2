

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/global/helpers/plat/linux/iface.h>



int init_iface_tcp_server(struct srv_tcp_state *state)
{
	int retval = 0;
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;

	for (uint16_t i = 0; i < max_conn; i++) {

	}


	return retval;
}

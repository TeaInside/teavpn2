
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/server/plat/linux/iface.h>







int teavpn_tcp_server(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	state.cfg = cfg;



	retval = init_iface_tcp_server(&state);
	if (retval < 0)
		goto out;






out:
	return retval;
}

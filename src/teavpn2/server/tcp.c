
#include <teavpn2/server/tcp.h>


int teavpn_server_tcp(struct srv_cfg *cfg)
{
	return teavpn_server_tcp_handler(cfg);
}


#include <teavpn2/server/tcp.h>

#if defined(__linux__)
#  include <teavpn2/server/linux/tcp.h>
#endif

int teavpn_server_tcp(struct srv_cfg *cfg)
{
	return teavpn_server_tcp_handler(cfg);
}

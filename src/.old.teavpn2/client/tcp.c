
#include <teavpn2/client/tcp.h>

#if defined(__linux__)
#  include <teavpn2/client/linux/tcp.h>
#endif

int teavpn_client_tcp(struct cli_cfg *cfg)
{
	return teavpn_client_tcp_handler(cfg);
}


#include <string.h>
#include <teavpn2/client/common.h>

#if defined(__linux__)
# include <teavpn2/client/linux/tcp.h>
#else
# error Target environment is not supported at the moment.
#endif

int teavpn_client_entry(int argc, char *argv[])
{
	struct cli_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (teavpn_client_argv_parse(argc, argv, &cfg) < 0)
		return 1;
	if (teavpn_client_cfg_parse(&cfg) < 0)
		return 1;

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn_tcp_client(&cfg);
	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;
	default:
		pr_error("Invalid socket type: %d", cfg.sock.type);
		return -EINVAL;
	}
}

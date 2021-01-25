
#include <string.h>
#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>

#if defined(__linux__)
# include <teavpn2/server/plat/linux/tcp.h>
#else
# error This compiler is not supported at the moment
#endif

int teavpn_server_entry(int argc, char *argv[])
{
	struct srv_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (server_argv_parse(argc, argv, &cfg) < 0)
		return 1;


	if (server_cfg_parse(&cfg) < 0)
		return 1;

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn_tcp_server(&cfg);

	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;

	default:
		pr_error("Invalid socket type: %d", cfg.sock.type);
		return -EINVAL;
	}
}

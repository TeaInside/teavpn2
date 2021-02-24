
#include <string.h>
#include <teavpn2/server/common.h>


int teavpn_server_entry(int argc, char *argv[])
{
	struct srv_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (teavpn_server_argv_parse(argc, argv, &cfg) < 0)
		return 1;
	if (teavpn_server_cfg_parse(&cfg) < 0)
		return 1;

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn_server_tcp(&cfg);
	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;
	default:
		pr_error("Invalid socket type: %d", cfg.sock.type);
		return -EINVAL;
	}
}


#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>

int teavpn_server_entry(int argc, char *argv[])
{
	int tmp;
	struct srv_cfg cfg;


	if (server_argv_parse(argc, argv, &cfg) < 0)
		return 1;


	if (server_cfg_parse(&cfg) < 0)
		return 1;


	switch (cfg.sock.type) {
	case SOCK_TCP:
		break;

	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;

	default:
		pr_error("Invalid socket type: %d", cfg.sock.type);
		return -EINVAL;
	}
}



#include <string.h>
#include <teavpn2/client/common.h>


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
		//return teavpn_client_tcp(&cfg);
	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;
	}

	pr_error("Invalid socket type: %u", cfg.sock.type);
		return -EINVAL;
}

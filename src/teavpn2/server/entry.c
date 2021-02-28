
#include <string.h>
#include <teavpn2/server/common.h>


static __always_inline bool validate_cfg(struct srv_cfg *cfg)
{
	if (cfg->data_dir == NULL) {
		pr_error("data_dir cannot be empty!\n");
		return false;
	}
	return true;
}


int teavpn_server_entry(int argc, char *argv[])
{
	struct srv_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));

	if (teavpn_server_argv_parse(argc, argv, &cfg) < 0)
		return 1;
	if (teavpn_server_cfg_parse(&cfg) < 0)
		return 1;
	if (!validate_cfg(&cfg))
		return 1;

	switch (cfg.sock.type) {
	case SOCK_TCP:
		return teavpn_server_tcp(&cfg);
	case SOCK_UDP:
		pr_error("UDP socket is not supported at the moment");
		return -ESOCKTNOSUPPORT;
	default:
		pr_error("Invalid socket type: %u", cfg.sock.type);
		return -EINVAL;
	}
}

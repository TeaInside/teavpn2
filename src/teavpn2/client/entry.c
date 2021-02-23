
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

	(void)argc;
	(void)argv;
	// if (teavpn_client_argv_parse(argc, argv, &cfg) < 0)
	// 	return 1;

	return 0;
}


#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>

int teavpn_server_entry(int argc, char *argv[])
{
	int tmp;
	int retval = 0;
	struct srv_cfg cfg;


	if (server_argv_parse(argc, argv, &cfg) < 0)
		return 1;


	if (server_cfg_parse(&cfg) < 0)
		return 1;

	return retval;
}


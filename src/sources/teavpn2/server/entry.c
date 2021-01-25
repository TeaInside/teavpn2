
#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>

int teavpn_server_entry(int argc, char *argv[])
{
	int tmp;
	int retval = 0;
	struct srv_cfg cfg;

	tmp = server_argv_parse(argc, argv, &cfg);

	if (tmp < 0)
		return tmp;

	



	return retval;
}

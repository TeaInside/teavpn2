
#ifndef __TEAVPN2__SERVER__ARGV_H
#define __TEAVPN2__SERVER__ARGV_H

#include <teavpn2/server/common.h>

int server_argv_parse(int argc, char *argv[], struct srv_cfg *cfg);


struct srv_argv {
	int		argc;
	const char	**argv;
	struct srv_cfg	*cfg;
	bool		exec;
};

#endif /* #ifndef __TEAVPN2__SERVER__ARGV_H */

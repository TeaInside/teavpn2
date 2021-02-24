
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef __TEAVPN2__CLIENT__LINUX__TCP_H
#define __TEAVPN2__CLIENT__LINUX__TCP_H

#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <teavpn2/client/common.h>

struct cli_tcp_state {
	bool			stop;
	int			net_fd;	/* Main TCP socket fd */

	struct cli_cfg		*cfg;
};

int teavpn_tcp_client(struct cli_cfg *cfg);

#endif /* #ifndef __TEAVPN2__CLIENT__LINUX__TCP_H */


#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef __TEAVPN2__SERVER__PLAT__LINUX__TCP_H
#define __TEAVPN2__SERVER__PLAT__LINUX__TCP_H

#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <teavpn2/server/common.h>

#define RECVBUFSIZ (1024ul * 7ul)
#define SENDBUFSIZ (1024ul * 7ul)

int teavpn_tcp_server(struct srv_cfg *cfg);

struct tcp_client {
	uint8_t		stop : 1;
	uint8_t		is_used : 1;
	uint8_t		is_connected : 1;
	uint8_t		is_authorized : 1;
	uint8_t		ht_mutex_active : 1; /* Should ht_mutex be destroyed? */

	int		tun_fd; /* FD for read/write from/to TUN/TAP queue */
	int		cli_fd; /* FD for data transfer with socket client */


	pthread_t	thread; /* Thread that handles the client */
	pthread_mutex_t	ht_mutex; /* Main thread waits before exits */

	char		username[255];

	struct sockaddr_in src_ip; /* Client source IP */

	uint16_t	err_c;	/* Error count */

	union {
		char send_buf[SENDBUFSIZ];
	};
	uint64_t	send_s; /* Valid bytes in recv_buf */
	uint64_t	send_c; /* Send count */


	union {
		char recv_buf[RECVBUFSIZ];
	};
	uint64_t	recv_s; /* Valid bytes in recv_buf */
	uint64_t	recv_c;	/* Recv count */
};

struct srv_tcp_state {
	bool			stop;
	int			net_fd;	/* Main TCP socket fd */

	nfds_t			nfds;
	struct srv_cfg		*cfg;
	struct pollfd 		*fds;

	uint16_t		n_online; /* Number of active clients */
	uint16_t		n_free_p; /* Index of unused client slot */
	struct tcp_client	*clients; /* Client slot array */
};

#endif /* #ifndef __TEAVPN2__SERVER__PLAT__LINUX__TCP_H */

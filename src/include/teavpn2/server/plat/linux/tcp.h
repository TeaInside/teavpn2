
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

int teavpn_tcp_server(struct srv_cfg *cfg);

typedef enum {
	EV_FIRST_CONNECT = 0, /* Wait for client to send first connect signal */
	EV_AUTHORIZATION = 1, /* Wait for client to send auth data */
	EV_ESTABLISHED   = 2, /* Data transfer is ready */
	EV_DISCONNECTED  = 3  /* Client has been disconnected */
} tcp_ev_state;

typedef enum __attribute__((packed)) {
	PKT_GET_INFO = 0,
	PKT_AUTH     = 1,
	PKT_DATA     = 2,
	PKT_CLOSE    = 3,
} tcp_pkt_type;

struct cli_tcp_pkt {
	uint16_t	len;
	tcp_pkt_type	type;
	char		data[4096];
} __attribute__((packed));

#define RECVBUFSIZ (sizeof(struct cli_tcp_pkt))
#define SENDBUFSIZ (sizeof(struct cli_tcp_pkt))


STATIC_ASSERT(sizeof(tcp_pkt_type) == 1, "sizeof(tcp_pkt_type) must be 1");
STATIC_ASSERT(offsetof(struct cli_tcp_pkt, len) == 0, "Bad alignment");
STATIC_ASSERT(offsetof(struct cli_tcp_pkt, type) == 2, "Bad alignment");
STATIC_ASSERT(offsetof(struct cli_tcp_pkt, data) == 3, "Bad alignment");
STATIC_ASSERT(sizeof(struct cli_tcp_pkt) >=
	      (sizeof(uint16_t) + sizeof(tcp_pkt_type) + sizeof(char [4096])),
	      "Bad alignment");

struct tcp_client {
	uint8_t		is_used : 1;
	uint8_t		is_connected : 1;
	uint8_t		is_authorized : 1;
	uint8_t		ht_mutex_active : 1; /* Should ht_mutex be destroyed? */

	int		tun_fd; /* FD for read/write from/to TUN/TAP queue */
	int		cli_fd; /* FD for data transfer with socket client */


	pthread_t	thread; /* Thread that handles the client */
	pthread_mutex_t	ht_mutex; /* Main thread waits before exits */

	struct sockaddr_in src_ip; /* Client source IP */

	uint16_t	arr_idx; /* Index of element in array slot (tcp state)*/

	uint8_t	err_c;	/* Error count */

	tcp_ev_state	ev_state; /* Event state */

	union {
		char send_buf[SENDBUFSIZ];
	};
	uint16_t	send_s; /* Valid bytes in recv_buf */
	uint64_t	send_c; /* Send count */


	union {
		char recv_buf[RECVBUFSIZ];
		struct cli_tcp_pkt cli_pkt;
	};
	uint16_t	recv_s; /* Valid bytes in recv_buf */
	uint64_t	recv_c;	/* Recv count */


	char		username[255];
	char		r_src_ip[IPV4LEN]; /* Human readable IP */
	uint16_t	r_src_port; /* Human readable port */
};

struct srv_client_stack {
	uint16_t		sp;
	uint16_t		max_sp;
	uint16_t		*block;
};

struct srv_tcp_state {
	bool			stop;
	int			net_fd;	/* Main TCP socket fd */

	nfds_t			nfds;
	struct srv_cfg		*cfg;
	struct pollfd 		*fds;

	uint16_t		n_online; /* Number of active clients */
	struct tcp_client	*clients; /* Client slot array */
	struct srv_client_stack stack;
};

#endif /* #ifndef __TEAVPN2__SERVER__PLAT__LINUX__TCP_H */

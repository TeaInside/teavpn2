
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef TEAVPN2__SERVER__LINUX__TCP_H
#define TEAVPN2__SERVER__LINUX__TCP_H

#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <teavpn2/server/common.h>

typedef enum {
	EV_FIRST_CONN    = 0, 	/* New connection */
	EV_AUTHORIZATION = 1,	/* Auth process */
	EV_ESTABLISHED   = 2,	/* Data transfer is ready */
	EV_DISCONNECTED  = 3,	/* Client has been disconnected */
} tcp_ev_state;

struct tcp_client {
	uint8_t			is_used : 1;	/* Is client slot being used? */
	uint8_t			is_conn : 1;	/* Is client slot connected? */
	uint8_t			is_auth : 1;	/* Is client slot authorized? */
	uint8_t		ht_mutex_active : 1;	/* For mutex destroy decision */
	int			tun_fd;		/* TUN/TAP fd queue */
	int			cli_fd;		/* Client TCP fd */
	pthread_t		thread;		/* Thread */
	pthread_mutex_t		ht_mutex;	/* Mutex */
	uint16_t		arr_idx; 	/* Index of element in array
						   slot (tcp state)*/
	uint8_t			err_c;		/* Error count */
	tcp_ev_state		ev_state; 	/* Event state */


	uint16_t		send_s;		/* Active bytes in send_buf */
	uint64_t		send_c;		/* Send count */
	union {
		char send_buf[SENDBUFSIZ];
	};

	uint16_t		recv_s;		/* Active bytes in recv_buf */
	uint64_t		recv_c;		/* Recv count */
	union {
		char recv_buf[RECVBUFSIZ];
	};

	char		username[255];		/* Client username */
	char		r_src_ip[IPV4LEN]; 	/* Human readable IP */
	uint16_t	r_src_port; 		/* Human readable port */

	struct sockaddr_in	src_ip; 	/* Client source IP */
};

struct srv_tcp_clstack {
	uint16_t		sp;		/* Stack pointer */
	uint16_t		max_sp;		/* Size of block */
	uint16_t		*slot;		/* Stack in array */
};

struct srv_tcp_state {
	bool			stop;		/* Stop indicator */
	int			net_fd;		/* Main net file descriptor */
	nfds_t			nfds;		/* Number of fds */
	struct pollfd		*fds;		/* fds for poll(2) syscall */
	struct srv_cfg		*cfg;		/* Pointer to server config */
	uint16_t		n_online;	/* Number of online client */
	struct tcp_client	*clients;	/* Client slot array */
	struct srv_tcp_clstack	stack;		/* Stack to gain O(1) lookup */
};


int teavpn_tcp_server(struct srv_cfg *cfg);

#endif /* #ifndef TEAVPN2__SERVER__LINUX__TCP_H */

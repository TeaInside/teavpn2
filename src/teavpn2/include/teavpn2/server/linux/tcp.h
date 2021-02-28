
#ifndef __TEAVPN2__SERVER__LINUX__TCP_H
#define __TEAVPN2__SERVER__LINUX__TCP_H

#include <poll.h>
#include <arpa/inet.h>
#include <teavpn2/server/common.h>
#include <teavpn2/client/linux/tcp.h>
#include <teavpn2/server/linux/tcp_packet.h>
#include <teavpn2/client/linux/tcp_packet.h>


typedef enum {
	CT_NEW			= 0,
	CT_ESTABLISHED		= 1,
	CT_AUTHENTICATED	= 2,
	CT_DISCONNECTED		= 3,
} srv_tcp_ctstate;

struct srv_tcp_client {
	uint8_t			is_used: 1;
	uint8_t			is_conn: 1;
	uint8_t			is_auth: 1;
	uint8_t			ht_mutx: 1;
	srv_tcp_ctstate		ctstate;
	int			cli_fd;
	uint16_t		arr_idx;
	uint8_t			err_c;

	uint64_t		send_c;
	uint64_t		recv_c;
	uint16_t		recv_s;
	union {
		char			recv_buf[sizeof(struct cli_tcp_pkt)];
		struct cli_tcp_pkt	cli_pkt;
	};

	char			username[255];
	char			src_ip[IPV4LEN + 1];
	uint16_t		src_port;
	struct sockaddr_in	src_data;
};

struct srv_tcp_clstack {
	uint16_t	sp;
	uint16_t	max_sp;
	uint16_t	*arr;
};

struct srv_tcp_state {
	int			net_fd;
	int			tun_fd;
	int			pipe_fd[2];
	nfds_t			nfds;
	struct pollfd		*fds;
	struct srv_cfg		*cfg;
	struct srv_tcp_client	*clients;
	struct srv_tcp_clstack	stack;
	union {
		char			send_buf[sizeof(struct srv_tcp_pkt)];
		struct srv_tcp_pkt	srv_pkt;
	};
	bool			stop;
};

int teavpn_server_tcp_handler(struct srv_cfg *cfg);

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__TCP_H */

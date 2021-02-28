
#ifndef __TEAVPN2__CLIENT__LINUX__TCP_H
#define __TEAVPN2__CLIENT__LINUX__TCP_H

#include <stdint.h>
#include <teavpn2/client/common.h>
#include <teavpn2/server/linux/tcp_packet.h>
#include <teavpn2/client/linux/tcp_packet.h>


struct cli_tcp_state {
	bool			is_auth;
	int			net_fd;
	int			tun_fd;
	struct cli_cfg		*cfg;

	uint8_t 		err_c;

	uint64_t		recv_c;
	uint16_t		recv_s;
	union {
		char			recv_buf[sizeof(struct srv_tcp_pkt)];
		struct srv_tcp_pkt	srv_pkt;
	};

	uint64_t		send_c;
	uint16_t		send_s;
	union {
		char			send_buf[sizeof(struct cli_tcp_pkt)];
		struct cli_tcp_pkt	cli_pkt;
	};
	bool			stop;
};

int teavpn_client_tcp_handler(struct cli_cfg *cfg);

#endif /* #ifndef __TEAVPN2__CLIENT__LINUX__TCP_H */

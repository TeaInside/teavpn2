// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CLIENT__LINUX__UDP_H
#define TEAVPN2__CLIENT__LINUX__UDP_H

#include <pthread.h>
#include <arpa/inet.h>
#include <teavpn2/packet.h>
#include <teavpn2/client/common.h>

#define EPLD_DATA_TUN	(1u << 0u)
#define EPLD_DATA_UDP	(1u << 1u)


/*
 * Epoll user data struct.
 */
struct epld_struct {
	int					fd;
	unsigned				type;
	uint16_t				idx;
};


struct cli_udp_state;


struct epl_thread {
	uint16_t				idx;
	pthread_t				thread;
	int					epoll_fd;
	struct cli_udp_state			*state;
	alignas(64) struct sc_pkt		pkt;
};


struct cli_udp_state {
	volatile bool				stop;
	int					sig;
	int					udp_fd;
	event_loop_t				evt_loop;
	int					*tun_fds;
	struct cli_cfg				*cfg;
	union {
		struct {
			struct epld_struct	*epl_udata;
			struct epl_thread	*epl_threads;
		};
	};
	alignas(64) struct sc_pkt		pkt;
};


extern int teavpn2_udp_client_epoll(struct cli_udp_state *state);


static inline size_t cli_pprep(struct cli_pkt *cli_pkt, uint8_t type,
			       uint16_t data_len, uint8_t pad_len)
{
	cli_pkt->type    = type;
	cli_pkt->len     = htons(data_len);
	cli_pkt->pad_len = pad_len;
	return data_len + PKT_MIN_LEN;
}


static inline size_t cli_pprep_handshake(struct cli_pkt *cli_pkt)
{
	struct pkt_handshake *hand = &cli_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;

	memset(hand, 0, sizeof(*hand));
	cur->ver = VERSION;
	cur->patch_lvl = PATCHLEVEL;
	cur->sub_lvl = SUBLEVEL;
	strncpy(cur->extra, EXTRAVERSION, sizeof(cur->extra));
	cur->extra[sizeof(cur->extra) - 1] = '\0';

	return cli_pprep(cli_pkt, TCLI_PKT_HANDSHAKE, (uint16_t)sizeof(*hand),
			 0);
}


static inline size_t cli_pprep_auth(struct cli_pkt *cli_pkt, const char *user,
				    const char *pass)
{
	struct pkt_auth *auth = &cli_pkt->auth;

	strncpy(auth->username, user, sizeof(auth->username));
	strncpy(auth->password, pass, sizeof(auth->password));
	auth->username[sizeof(auth->username) - 1] = '\0';
	auth->password[sizeof(auth->password) - 1] = '\0';

	return cli_pprep(cli_pkt, TCLI_PKT_AUTH, (uint16_t)sizeof(*auth), 0);
}



#endif /* #ifndef TEAVPN2__CLIENT__LINUX__UDP_H */

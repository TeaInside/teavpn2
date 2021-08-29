// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__LINUX__UDP_H
#define TEAVPN2__SERVER__LINUX__UDP_H

#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <stdatomic.h>
#include <teavpn2/packet.h>
#include <teavpn2/client/common.h>

#define EPLD_DATA_TUN		(1u << 0u)
#define EPLD_DATA_UDP		(1u << 1u)
#define EPOLL_EVT_ARR_NUM	(16)

#define UDP_SESS_NUM		(32u)


/*
 * Epoll user data struct.
 */
struct epld_struct {
	int					fd;
	unsigned				type;
	uint16_t				idx;
};


struct srv_udp_state;


struct epl_thread {
	uint16_t				idx;
	pthread_t				thread;
	int					epoll_fd;
	int					epoll_timeout;
	struct srv_udp_state			*state;
	struct epoll_event			events[EPOLL_EVT_ARR_NUM];
	alignas(64) struct sc_pkt		pkt;
};


struct udp_sess {
	uint32_t				src_addr;
	uint16_t				src_port;
	uint16_t				idx;
	uint16_t				err_c;
	bool					is_authenticated;
	bool					is_connected;
	time_t					last_act;
};


struct map_bucket {
	struct map_bucket			*next;
	struct udp_sess				*sess;
};


struct srv_udp_state {
	volatile bool				stop;
	int					sig;
	int					udp_fd;
	event_loop_t				evt_loop;
	int					*tun_fds;
	struct srv_cfg				*cfg;
	_Atomic(uint16_t)			ready_thread;
	struct udp_sess				*sess;
	struct map_bucket			(*sess_map)[0x100];
	union {
		struct {
			struct epld_struct	*epl_udata;
			struct epl_thread	*epl_threads;
		};
	};
};


extern int teavpn2_udp_server_epoll(struct srv_udp_state *state);


static inline void reset_udp_session(struct udp_sess *sess, uint16_t idx)
{
	sess->last_act = 0;
	sess->src_addr = 0;
	sess->src_port = 0;
	sess->idx = idx;
	sess->err_c = 0;
	sess->is_authenticated = false;
	sess->is_connected = false;
}

#endif /* #ifndef TEAVPN2__SERVER__LINUX__UDP_H */

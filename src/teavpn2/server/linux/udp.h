// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__LINUX__UDP_H
#define TEAVPN2__SERVER__LINUX__UDP_H

#include <pthread.h>
#include <sys/epoll.h>
#include <stdatomic.h>
#include <teavpn2/client/common.h>

#define EPLD_DATA_TUN		(1u << 0u)
#define EPLD_DATA_UDP		(1u << 1u)
#define EPOLL_EVT_ARR_NUM	(16)


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
};


struct srv_udp_state {
	volatile bool				stop;
	int					sig;
	int					udp_fd;
	event_loop_t				evt_loop;
	int					*tun_fds;
	struct srv_cfg				*cfg;
	_Atomic(uint16_t)			ready_thread;
	union {
		struct {
			struct epld_struct	*epl_udata;
			struct epl_thread	*epl_threads;
		};
	};
};


extern int teavpn2_udp_server_epoll(struct srv_udp_state *state);

#endif /* #ifndef TEAVPN2__SERVER__LINUX__UDP_H */

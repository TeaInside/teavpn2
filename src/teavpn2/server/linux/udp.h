// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__LINUX__UDP_H
#define TEAVPN2__SERVER__LINUX__UDP_H

#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <stdatomic.h>
#include <teavpn2/mutex.h>
#include <teavpn2/stack.h>
#include <teavpn2/packet.h>
#include <teavpn2/client/common.h>

#define EPLD_DATA_TUN		(1u << 0u)
#define EPLD_DATA_UDP		(1u << 1u)
#define EPOLL_EVT_ARR_NUM	(16)

#define UDP_SESS_TIMEOUT	(10)

#define UDP_SESS_NUM		(32u)

#define UDP_SESS_MAX_ERR	(10u)

#define W_IP(CLIENT) 		((CLIENT)->str_addr), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 			"%s:%d (%s) (cli_idx=%hu)"


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
	_Atomic(bool)				is_online;
	uint16_t				idx;
	pthread_t				thread;
	int					epoll_fd;
	int					epoll_timeout;
	struct srv_udp_state			*state;
	struct epoll_event			events[EPOLL_EVT_ARR_NUM];
	alignas(64) struct sc_pkt		pkt;
};


struct udp_map_bucket;


struct udp_sess {
	uint32_t				ipv4_iff;
	uint32_t				src_addr;
	uint16_t				src_port;
	uint16_t				idx;
	uint16_t				err_c;
	time_t					last_touch;
	struct sockaddr_in			addr;
	char					str_addr[IPV4_L];
	char					username[0x100];
	bool					is_authenticated;
	_Atomic(bool)				is_connected;
};


struct udp_map_bucket {
	struct udp_map_bucket			*next;
	struct udp_sess				*sess;
};


struct srv_udp_state {
	volatile bool				stop;
	volatile bool				in_emergency;
	bool					threads_wont_exit;
	bool					need_remove_iff;
	int					sig;
	int					udp_fd;
	event_loop_t				evt_loop;
	int					*tun_fds;
	struct srv_cfg				*cfg;
	_Atomic(uint16_t)			ready_thread;

	_Atomic(uint16_t)			active_sess;
	struct udp_sess				*sess;

	struct bt_stack				sess_stk;
	struct tmutex				sess_stk_lock;

	struct udp_map_bucket			(*sess_map)[0x100];
	struct tmutex				sess_map_lock;

	uint16_t				(*ipv4_map)[0x100];

	union {
		struct {
			struct epld_struct	*epl_udata;
			struct epl_thread	*epl_threads;
		};
	};
};


extern int teavpn2_udp_server_epoll(struct srv_udp_state *state);

extern struct udp_sess *map_find_udp_sess(struct srv_udp_state *state,
					  uint32_t addr, uint16_t port);

extern struct udp_sess *get_udp_sess(struct srv_udp_state *state, uint32_t addr,
				     uint16_t port);

extern int put_udp_session(struct srv_udp_state *state,
			   struct udp_sess *cur_sess);


static inline void reset_udp_session(struct udp_sess *sess, uint16_t idx)
{
	sess->ipv4_iff = 0;
	sess->src_addr = 0;
	sess->src_port = 0;
	sess->idx = idx;
	sess->err_c = 0;
	sess->last_touch = 0;
	sess->is_authenticated = false;
	atomic_store(&sess->is_connected, false);
	sess->str_addr[0] = '\0';
	sess->username[0] = '_';
	sess->username[1] = '\0';
	memset(&sess->addr, 0, sizeof(sess->addr));
}


static inline size_t srv_pprep(struct srv_pkt *srv_pkt, uint8_t type,
			       uint16_t data_len, uint8_t pad_len)
{
	srv_pkt->type    = type;
	srv_pkt->len     = htons(data_len);
	srv_pkt->pad_len = pad_len;
	return data_len + PKT_MIN_LEN;
}


static inline size_t srv_pprep_handshake_reject(struct srv_pkt *srv_pkt,
						uint8_t reason,
						const char *msg)
{
	struct pkt_handshake_reject *rej = &srv_pkt->hs_reject;

	rej->reason = reason;
	if (!msg) {
		memset(rej->msg, 0, sizeof(rej->msg));
	} else {
		strncpy2(rej->msg, msg, sizeof(rej->msg));
		rej->msg[sizeof(rej->msg) - 1] = '\0';
	}

	return srv_pprep(srv_pkt, TSRV_PKT_HANDSHAKE_REJECT,
			 (uint16_t)sizeof(*rej), 0);
}


static inline size_t srv_pprep_handshake(struct srv_pkt *srv_pkt)
{
	struct pkt_handshake *hand = &srv_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;

	memset(hand, 0, sizeof(*hand));
	cur->ver = VERSION;
	cur->patch_lvl = PATCHLEVEL;
	cur->sub_lvl = SUBLEVEL;
	strncpy2(cur->extra, EXTRAVERSION, sizeof(cur->extra));
	cur->extra[sizeof(cur->extra) - 1] = '\0';

	return srv_pprep(srv_pkt, TSRV_PKT_HANDSHAKE, (uint16_t)sizeof(*hand),
			 0);
}


static inline int get_unix_time(time_t *tm)
{
	int ret;
	struct timeval tv;
	ret = gettimeofday(&tv, NULL);
	if (unlikely(ret)) {
		ret = errno;
		pr_err("gettimeofday(): " PRERF, PREAR(ret));
		return -ret;
	}
	*tm = tv.tv_sec;
	return ret;
}


static inline int udp_sess_tv_update(struct udp_sess *cur_sess)
{
	return get_unix_time(&cur_sess->last_touch);
}


static inline void add_ipv4_route_map(uint16_t (*ipv4_map)[0x100], uint32_t addr,
				      uint16_t idx)
{
	/*
	 * IPv4 looks like this:
	 *     AA.BB.CC.DD
	 *
	 * DD is the byte0
	 * CC is the byte1
	 */

	uint16_t byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	ipv4_map[byte0][byte1] = idx + 1u;
}


static inline void del_ipv4_route_map(uint16_t (*ipv4_map)[0x100], uint32_t addr)
{
	/*
	 * IPv4 looks like this:
	 *     AA.BB.CC.DD
	 *
	 * DD is the byte0
	 * CC is the byte1
	 */

	uint16_t byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	ipv4_map[byte0][byte1] = 0;
}


static inline int32_t get_route_map(uint16_t (*ipv4_map)[0x100], uint32_t addr)
{
	uint16_t ret, byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	ret   = ipv4_map[byte0][byte1];

	if (ret == 0) {
		/* Unmapped address. */
		return -1;
	}

	return (int32_t)(ret - 1);
}


#endif /* #ifndef TEAVPN2__SERVER__LINUX__UDP_H */


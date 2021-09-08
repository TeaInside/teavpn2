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


#define EPOLL_EVT_ARR_NUM 3u
#define UDP_SESS_MAX_ERR 5u

/*
 * UDP session struct.
 *
 * Each client has its own UDP session struct.
 */
struct udp_sess {
	/*
	 * Private IP address (virtual network interface).
	 */
	uint32_t				ipv4_iff;

	/*
	 * @src_addr is the UDP session source address.
	 * @src_port is the UDP session source port.
	 */
	uint32_t				src_addr;
	uint16_t				src_port;

	/*
	 * UDP sessions are stored in the array, this
	 * @idx contains the index position of each
	 * instance.
	 */
	uint16_t				idx;

	/*
	 * Error counter.
	 */
	uint16_t				err_c;

	/*
	 * UDP is stateless, we may not know whether the
	 * client is still online or not, @last_act can
	 * be used to handle timeout for session closing
	 * in case we have abnormal session termination.
	 */
	time_t					last_act;

	/*
	 * Big endian src_addr and src_port for sendto() call.
	 */
	struct sockaddr_in			addr;

	/*
	 * Session username.
	 */
	char					username[0x100];

	/*
	 * Human readable of @src_addr.
	 */
	char					str_src_addr[IPV4_L];

	bool					is_authenticated;
	_Atomic(bool)				is_connected;
};


/*
 * Bucket for session map. We can handle collision with singly linked
 * list here.
 */
struct udp_map_bucket;
struct udp_map_bucket {
	struct udp_map_bucket			*next;
	struct udp_sess				*sess;
};


struct srv_udp_state;


struct epl_thread {
	/*
	 * Pointer to the UDP state struct.
	 */
	struct srv_udp_state			*state;

	/*
	 * pthread reference.
	 */
	pthread_t				thread;

	int					epoll_fd;
	int					epoll_timeout;
	struct epoll_event			events[EPOLL_EVT_ARR_NUM];

	/*
	 * Is this thread online?
	 */
	_Atomic(bool)				is_online;

	uint16_t				idx;
	struct sc_pkt				*pkt;
};


struct srv_udp_state {
	/*
	 * @stop is false when event loop is supposed to run.
	 * @stop is true when event loop needs to be stopped.
	 */
	volatile bool				stop;

	/*
	 * @in_emergency will be true in case we run out of
	 * buffer, or when we are in the similar urgent
	 * situation that needs more attention.
	 */
	volatile bool				in_emergency;

	/*
	 * When we're exiting, the main thread will wait for
	 * the subthreads to exit for the given timeout. If
	 * the subthreads won't exit, @threads_wont_exit is
	 * set to true. This is an indicator that we are not
	 * allowed to free() and close() the resources as it
	 * may lead to UAF bug.
	 */
	bool					threads_wont_exit;

	/*
	 * @need_remove_iff is true when we need to remove
	 * virtual network interface configuration before
	 * exit, otherwise it's false.
	 */
	bool					need_remove_iff;


	/*
	 * @sig should contain signal after signal interrupt
	 * handler is called. If the signal interrupt handle
	 * is never called, the value of @sig should be -1.
	 */
	int					sig;

	event_loop_t				evt_loop;
	int					udp_fd;
	struct srv_cfg				*cfg;

	/*
	 * Stack to retrieve free UDP session index in O(1)
	 * time complexity.
	 */
	struct bt_stack				sess_stk;
	struct tmutex				sess_stk_lock;

	/*
	 * Small hash table for session lookup after recvfrom().
	 */
	struct udp_map_bucket			(*sess_map)[0x100];
	struct tmutex				sess_map_lock;

	/*
	 * @sess_arr is an array of UDP sessions.
	 */
	struct udp_sess				*sess_arr;

	/*
	 * Number of active sessions in @sess_arr.
	 */
	_Atomic(uint16_t)			n_on_sess;


	_Atomic(uint16_t)			n_on_threads;


	/*
	 * @tun_fds is an array of TUN file descriptors.
	 * Number of TUN file descriptor can be more than
	 * one because on Linux it's possible to parallelize
	 * the read/write to TUN fd.
	 */
	int					*tun_fds;

	/*
	 * Map @ipv4_ff to @sess_arr index.
	 */
	uint16_t				(*ipv4_map)[0x100];

	union {
		/*
		 * For epoll event loop.
		 */
		struct {
			struct epl_thread	*epl_threads;
		};


		/*
		 * For io_uring event loop.
		 */
		struct {
			struct iou_thread	*iou_threads;
		};
	};
};


#define W_IP(CLIENT) 	((CLIENT)->str_src_addr), ((CLIENT)->src_port)
#define W_UN(CLIENT) 	((CLIENT)->username)
#define W_IU(CLIENT) 	W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 		"%s:%d (%s) (cli_idx=%hu)"


extern int teavpn2_udp_server_epoll(struct srv_udp_state *state);
extern int teavpn2_udp_server_io_uring(struct srv_udp_state *state);
extern struct udp_sess *map_find_udp_sess(struct srv_udp_state *state,
					  uint32_t addr, uint16_t port);
extern struct udp_sess *get_udp_sess(struct srv_udp_state *state, uint32_t addr,
				     uint16_t port);
extern int put_udp_session(struct srv_udp_state *state, struct udp_sess *sess);


static __always_inline void reset_udp_session(struct udp_sess *sess, uint16_t idx)
{
	sess->ipv4_iff = 0u;
	sess->src_addr = 0u;
	sess->src_port = 0u;
	sess->idx      = idx;
	sess->err_c    = 0u;
	sess->last_act = 0;
	memset(&sess->addr, 0, sizeof(sess->addr));
	sess->username[0] = '_';
	sess->username[1] = '\0';
	sess->is_authenticated = false;
	atomic_store(&sess->is_connected, false);
}


static __always_inline size_t srv_pprep(struct srv_pkt *srv_pkt, uint8_t type,
					uint16_t data_len, uint8_t pad_len)
{
	srv_pkt->type    = type;
	srv_pkt->len     = htons(data_len);
	srv_pkt->pad_len = pad_len;
	return (size_t)(data_len + PKT_MIN_LEN);
}


static __always_inline size_t srv_pprep_handshake_reject(struct srv_pkt *srv_pkt,
							 uint8_t reason,
							 const char *msg)
{
	struct pkt_handshake_reject *rej = &srv_pkt->hs_reject;
	uint16_t data_len = (uint16_t)sizeof(*rej);

	rej->reason = reason;
	if (!msg)
		memset(rej->msg, 0, sizeof(rej->msg));
	else
		strncpy2(rej->msg, msg, sizeof(rej->msg));

	return srv_pprep(srv_pkt, TSRV_PKT_HANDSHAKE_REJECT, data_len, 0);
}


static __always_inline size_t srv_pprep_handshake(struct srv_pkt *srv_pkt)
{
	struct pkt_handshake *hand = &srv_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;
	uint16_t data_len = (uint16_t)sizeof(*hand);

	memset(hand, 0, sizeof(*hand));

	cur->ver       = VERSION;
	cur->patch_lvl = PATCHLEVEL;
	cur->sub_lvl   = SUBLEVEL;
	strncpy2(cur->extra, EXTRAVERSION, sizeof(cur->extra));

	return srv_pprep(srv_pkt, TSRV_PKT_HANDSHAKE, data_len, 0);
}


static __always_inline int get_unix_time(time_t *tm)
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


static __always_inline int udp_sess_tv_update(struct udp_sess *cur_sess)
{
	return get_unix_time(&cur_sess->last_act);
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

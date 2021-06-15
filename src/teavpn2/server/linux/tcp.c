// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TeaVPN2 server core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <linux/ip.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>

#include <teavpn2/tcp_pkt.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

#include <bluetea/lib/mutex.h>
#include <bluetea/lib/string.h>


#define EPL_MAP_SIZE		0x10000u
#define EPL_MAP_TO_NOP		0x00000u
#define EPL_MAP_TO_TCP		0x00001u
#define EPL_MAP_TO_TUN		0x00002u
#define EPL_MAP_SHIFT		0x00003u
#define EPL_IN_EVT		(EPOLLIN | EPOLLPRI | EPOLLHUP)
#define EPL_WAIT_ARRSIZ		16
#define CLIENT_MAX_ERRC		20u



/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU 			"%s:%d (%s)"


struct server_thread {
	_Atomic(bool)			is_online;
	pthread_t			thread;
	struct server_state		*state;
	int				epoll_fd;

	/* `idx` is the index where it's stored in the thread array. */
	uint16_t			idx;

	/* `read_s` is the valid bytes in the below union buffer. */
	size_t				read_s;

	union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};
};


struct client_slot {
	bool				is_authenticated;
	bool				is_encrypted;
	int				cli_fd;
	char				username[0x100u];

	/* Human readable src_ip and src_port */
	char				src_ip[IPV4_L];
	uint16_t			src_port;

	/* `idx` is the index where it's stored in the client slot array. */
	uint16_t			idx;

	uint16_t			err_count;
	struct bt_mutex			lock;

	/* `recv_s` is the valid bytes in the below union buffer. */
	size_t				recv_s;

	union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};
};


struct client_stack {
	struct bt_mutex			lock;
	uint16_t			*arr;
	uint16_t			sp;
	uint16_t			max_sp;
};


struct server_state {
	int				intr_sig;
	int				tcp_fd;
	int				*tun_fds;
	uint16_t			*epoll_map;

	/* Client slot array */
	struct client_slot		*clients;

	/* Thread array */
	struct server_thread		*threads;

	struct srv_cfg			*cfg;
	_Atomic(uint32_t)		tr_assign;
	_Atomic(uint32_t)		online_tr;
	struct client_stack		cl_stk;
	bool				stop;
};


static struct server_state *g_state;


static void handle_interrupt(int sig)
{
	struct server_state *state = g_state;

	printf("\nInterrupt caught: %d\n", sig);
	if (state) {
		state->stop = true;
		state->intr_sig = sig;
	} else {
		panic("Bug: handle_interrupt is called when g_state is NULL\n");
		abort();
	}
}


static int validate_cfg(struct srv_cfg *cfg)
{
	if (!cfg->sys.thread) {
		pr_err("Number of thread cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.dev) {
		pr_err("cfg->iface.dev cannot be empty");
		return -EINVAL;
	}

	if (!cfg->iface.mtu) {
		pr_err("cfg->iface.mtu cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.ipv4) {
		pr_err("cfg->iface.ipv4 cannot be empty");
		return -EINVAL;
	}

	if (!*cfg->iface.ipv4_netmask) {
		pr_err("cfg->iface.ipv4_netmask cannot be empty");
		return -EINVAL;
	}

	return 0;
}


static void *calloc_wrp(size_t nmemb, size_t size)
{
	void *ret = calloc(nmemb, size);
	if (unlikely(ret == NULL)) {
		int err = errno;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}
	return ret;
}


static int init_state_tun_fds(struct server_state *state)
{
	int *tun_fds;
	struct srv_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	tun_fds = calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state_epoll_map(struct server_state *state)
{
	uint16_t *epoll_map;

	epoll_map = calloc_wrp(EPL_MAP_SIZE, sizeof(*epoll_map));
	if (unlikely(!epoll_map))
		return -ENOMEM;

	for (size_t i = 0; i < EPL_MAP_SIZE; i++)
		epoll_map[i] = EPL_MAP_TO_NOP;

	state->epoll_map = epoll_map;
	return 0;
}


static void reset_client_state(struct client_slot *client, size_t idx)
{
	client->is_authenticated  = false;
	client->is_encrypted      = false;
	client->cli_fd            = -1;
	client->username[0]       = '_';
	client->username[1]       = '\0';
	client->src_ip[0]         = '\0';
	client->src_port          = 0u;
	client->idx               = (uint16_t)idx;
	client->err_count         = 0u;
	client->recv_s            = 0u;
}


static int init_state_client_slot_array(struct server_state *state)
{
	struct client_slot *clients;
	size_t nn = state->cfg->sock.max_conn;

	clients = calloc_wrp(nn, sizeof(*clients));
	if (unlikely(!clients))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		reset_client_state(&clients[i], i);

	state->clients = clients;
	return 0;
}


static int init_state_threads(struct server_state *state)
{
	struct server_thread *threads;
	struct srv_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	threads = calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++) {
		threads[i].epoll_fd = -1;
		threads[i].state = state;
		threads[i].idx = (uint16_t)i;
	}

	state->threads = threads;
	return 0;
}



static int init_state(struct server_state *state)
{
	int ret = 0;

	state->intr_sig    = -1;
	state->tcp_fd      = -1;
	state->tun_fds     = NULL;
	state->epoll_map   = NULL;
	state->clients     = NULL;
	state->stop        = false;
	atomic_store(&state->tr_assign, 0);
	atomic_store(&state->online_tr, 0);

	ret = validate_cfg(state->cfg);
	if (unlikely(ret))
		return ret;

	ret = init_state_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_epoll_map(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_client_slot_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);
	return ret;
}


static int init_iface(struct server_state *state)
{
	int ret;
	size_t i;
	int *tun_fds = state->tun_fds;
	size_t nn = state->cfg->sys.thread;
	uint16_t *epoll_map = state->epoll_map;
	struct if_info *iff = &state->cfg->iface;

	prl_notice(3, "Allocating virtual network interface...");
	for (i = 0; i < nn; i++) {
		int tmp_fd;
		const short tun_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

		prl_notice(5, "Allocating TUN fd %zu...", i);
		tmp_fd = tun_alloc(iff->dev, tun_flags);
		if (unlikely(tmp_fd < 0))
			return tmp_fd;

		ret = fd_set_nonblock(tmp_fd);
		if (unlikely(ret < 0)) {
			close(tmp_fd);
			return ret;
		}

		tun_fds[i] = tmp_fd;
		epoll_map[tmp_fd] = EPL_MAP_TO_TUN;
	}

	if (unlikely(!teavpn_iface_up(iff))) {
		pr_err("Cannot bring virtual network interface up");
		return -ENETDOWN;
	}

	return 0;	
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret = 0;
	struct server_state *state;

	state = malloc(sizeof(*state));
	if (unlikely(!state)) {
		ret = errno;
		pr_err("malloc(): " PRERF, PREAR(ret));
		return -ret;
	}
	memset(state, 0, sizeof(*state));


	state->cfg = cfg;
	g_state    = state;


	ret = init_state(state);
	if (unlikely(ret))
		goto out;


	ret = init_iface(state);
	if (unlikely(ret))
		goto out;

out:
	free(state);
	return ret;
}

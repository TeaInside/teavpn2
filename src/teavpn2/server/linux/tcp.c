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


struct srv_thread {
	_Atomic(bool)			is_online;
	pthread_t			thread;
	struct srv_state		*state;
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


struct srv_state {
	int				intr_sig;
	int				tcp_fd;
	int				*tun_fds;
	uint16_t			*epoll_map;

	/* Client slot array */
	struct client_slot		*clients;

	/* Thread array */
	struct srv_thread		*threads;

	struct srv_cfg			*cfg;
	_Atomic(uint32_t)		tr_assign;
	_Atomic(uint32_t)		online_tr;
	struct client_stack		cl_stk;
	bool				stop;
};


static struct srv_state *g_state;


static void handle_interrupt(int sig)
{
	struct srv_state *state = g_state;

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


static int init_state_tun_fds(struct srv_state *state)
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


static int init_state_epoll_map(struct srv_state *state)
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


static int init_state_client_slot_array(struct srv_state *state)
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


static int init_state_threads(struct srv_state *state)
{
	struct srv_thread *threads;
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


static int32_t clstk_push(struct client_stack *cl_stk, uint16_t idx)
{
	uint16_t sp = cl_stk->sp;

	if (unlikely(sp == 0))
		/*
		 * Stack is full.
		 */
		return -1;

	cl_stk->arr[--sp] = idx;
	cl_stk->sp = sp;
	return (int32_t)idx;
}


static int32_t clstk_pop(struct client_stack *cl_stk)
{
	int32_t ret;
	uint16_t sp = cl_stk->sp;
	uint16_t max_sp = cl_stk->max_sp;

	assert(sp <= max_sp);
	if (unlikely(sp == max_sp))
		/*
		 * Stack is empty.
		 */
		return -1;

	ret = (int32_t)cl_stk->arr[sp++];
	cl_stk->sp = sp;
	return ret;
}


static int init_state_client_stack(struct srv_state *state)
{
	int ret;
	uint16_t *arr;
	size_t nn = state->cfg->sock.max_conn;
	struct client_stack *cl_stk = &state->cl_stk;

	arr = calloc_wrp(nn, sizeof(*arr));
	if (unlikely(!arr))
		return -ENOMEM;

	ret = bt_mutex_init(&cl_stk->lock, NULL);
	if (unlikely(ret)) {
		pr_err("mutex_init(&cl_stk->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}


	cl_stk->sp = (uint16_t)nn;
	cl_stk->max_sp = (uint16_t)nn;
	cl_stk->arr = arr;

#ifndef NDEBUG
/*
 * Test only.
 */
{
	int32_t ret;

	/*
	 * Push stack.
	 */
	for (size_t i = 0; i < nn; i++) {
		ret = clstk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}

	/*
	 * Push full stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = clstk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}

	/*
	 * Pop stack.
	 */
	for (size_t i = nn; i--;) {
		ret = clstk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}


	/*
	 * Pop empty stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = clstk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}
}
#endif

	for (size_t i = 0; i < nn; i++)
		clstk_push(cl_stk, (uint16_t)i);

	BT_ASSERT(cl_stk->sp == 0);
	return 0;
}


static int init_state(struct srv_state *state)
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

	ret = init_state_client_stack(state);
	if (unlikely(ret))
		return ret;

	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);
	return ret;
}


static int socket_setup(int cli_fd, struct srv_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;

	y = 1;
	ret = setsockopt(cli_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(ret < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}


	y = 6;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}


	y = 50000;
	ret = setsockopt(cli_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	ret = fd_set_nonblock(cli_fd);
	if (unlikely(ret < 0))
		return ret;

	/*
	 * TODO: Use cfg to set some socket options.
	 */
	(void)cfg;
	return ret;
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return ret;
}


static int socket_setup_main_tcp(int tcp_fd, struct srv_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;


	y = 1;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	/*
	 * TODO: Use cfg to set some socket options.
	 */
	(void)cfg;
	return socket_setup(tcp_fd, state);
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return ret;
}


static int init_iface(struct srv_state *state)
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


static int init_tcp_socket(struct srv_state *state)
{
	int ret;
	int tcp_fd;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;


	prl_notice(0, "Creating TCP socket...");
	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(tcp_fd < 0)) {
		ret = errno;
		pr_err("socket(): " PRERF, PREAR(ret));
		return -ret;
	}


	prl_notice(0, "Setting socket file descriptor up...");
	ret = socket_setup_main_tcp(tcp_fd, state);
	if (unlikely(ret < 0))
		goto out_err;


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);


	ret = bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("bind(): " PRERF, PREAR(ret));
		goto out_err;
	}


	ret = listen(tcp_fd, sock->backlog);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("listen(): " PRERF, PREAR(ret));
		goto out_err;
	}


	state->epoll_map[tcp_fd] = EPL_MAP_TO_TCP;
	state->tcp_fd = tcp_fd;
	prl_notice(0, "Listening on %s:%d...", sock->bind_addr,
		   sock->bind_port);

	return 0;
out_err:
	close(tcp_fd);
	return -ret;
}


static void close_tun_fds(int *tun_fds, size_t nn)
{
	if (!tun_fds)
		return;

	for (size_t i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;

		prl_notice(3, "Closing tun_fds[%zu] (%d)...", i, tun_fds[i]);
		close(tun_fds[i]);
	}
}


static void close_epoll_threads(struct srv_thread *threads, size_t nn)
{
	if (!threads)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct srv_thread *thread = &threads[i];
		int epoll_fd = thread->epoll_fd;

		if (epoll_fd == -1)
			continue;

		prl_notice(3, "Closing threads[%zu].epoll_fd (%d)...", i,
			   epoll_fd);
		close(epoll_fd);
	}
}


static void close_clients(struct client_slot *clients, size_t nn)
{
	if (!clients)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct client_slot *client = &clients[i];
		int cli_fd = client->cli_fd;

		if (cli_fd == -1)
			continue;

		prl_notice(3, "Closing clients[%zu].cli_fd (%d)...", i, cli_fd);
		close(cli_fd);
	}
}


static void close_fds(struct srv_state *state)
{
	int tcp_fd = state->tcp_fd;

	close_tun_fds(state->tun_fds, state->cfg->sys.thread);
	if (tcp_fd != -1) {
		prl_notice(3, "Closing state->tcp_fd (%d)...", tcp_fd);
		close(tcp_fd);
	}
	close_epoll_threads(state->threads, state->cfg->sys.thread);
	close_clients(state->clients, state->cfg->sock.max_conn);
}


static void destroy_state(struct srv_state *state)
{
	close_fds(state);
	bt_mutex_destroy(&state->cl_stk.lock);
	free(state->cl_stk.arr);
	free(state->tun_fds);
	free(state->threads);
	free(state->clients);
	free(state->epoll_map);
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret = 0;
	struct srv_state *state;

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

	ret = init_tcp_socket(state);
	if (unlikely(ret))
		goto out;
out:
	destroy_state(state);
	free(state);
	return ret;
}

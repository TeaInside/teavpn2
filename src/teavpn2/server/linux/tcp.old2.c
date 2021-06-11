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

#include <teavpn2/lock.h>
#include <teavpn2/tcp_pkt.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

#include <bluetea/lib/string.h>

#define CALCULATE_STATS		1

#define EPL_MAP_SIZE		0x10000u
#define EPL_MAP_TO_NOP		0x00000u
#define EPL_MAP_TO_TCP		0x00001u
#define EPL_MAP_TO_TUN		0x00002u
#define EPL_MAP_SHIFT		0x00003u

#define EPL_IN_EVT		(EPOLLIN | EPOLLPRI | EPOLLHUP)
#define EPL_WAIT_NUM		16

#define DO_BUSY_RECV		1
#define BUSY_RECV_COUNT		10
#define DO_BUSY_READ		1
#define BUSY_READ_COUNT		10

#define CLIENT_MAX_ERRC		20u

/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU 			"%s:%d (%s)"

struct srv_thread {
	_Atomic(bool)			is_on;
	pthread_t			thread;
	struct srv_state		*state;
	int				epoll_fd;
	uint16_t			thread_idx;
	size_t				pkt_len;
	union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};
};


struct srv_client {
	bool				is_auth;
	bool				encrypted;
	int				cli_fd;
	char				username[255u];
	char				src_ip[IPV4_L];
	uint16_t			src_port;
	uint16_t			idx;
	uint16_t			err_count;
	size_t				recv_s;
	union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};
	struct tea_mutex		lock;
};


struct client_stack {
	struct tea_mutex		lock;
	uint16_t			*arr;
	uint16_t			sp;
	uint16_t			max_sp;
};


struct srv_state {
	int				intr_sig;
	int				tcp_fd;
	int				*tun_fds;
	struct srv_thread		*threads;

	/* Client slot array */
	struct srv_client		*clients;

	struct client_stack		cl_stk;

	struct srv_cfg 			*cfg;
	uint16_t			*epoll_map;
	uint16_t			thread_assignee;
	bool				stop_el;
	_Atomic(uint16_t)		on_thread_c;
};


enum clevt {
	CLE_OK		= 0u,
	CLE_ERROR	= (1u << 0u),
	CLE_CLOSE	= (1u << 1u),
};


static struct srv_state *g_state = NULL;


static void handle_interrupt(int sig)
{
	struct srv_state *state = g_state;

	if (state->intr_sig != -1) {
		state->stop_el = true;
		return;
	}

	printf("\nInterrupt caught: %d\n", sig);
	if (state) {
		state->stop_el  = true;
		state->intr_sig = sig;
	} else {
		panic("Bug: handle_interrupt found that g_state is NULL\n");
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


static int init_tun_fds_array(struct srv_state *state)
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
		threads[i].thread_idx = (uint16_t)i;
	}

	state->threads = threads;
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


static void reset_client_state(struct srv_client *client, size_t idx)
{
	client->is_auth       = false;
	client->encrypted     = false;
	client->cli_fd        = -1;
	client->username[0]   = '_';
	client->username[1]   = '\0';
	client->src_ip[0]     = '\0';
	client->src_port      = 0u;
	client->idx           = (uint16_t)idx;
	client->err_count     = 0u;
	client->recv_s        = 0u;
}


static int init_state_clients(struct srv_state *state)
{
	int ret;
	uint16_t *arr;
	struct srv_client *clients;
	size_t nn = state->cfg->sock.max_conn;
	struct client_stack *cl_stk = &state->cl_stk;

	clients = calloc_wrp(nn, sizeof(*clients));
	if (unlikely(!clients))
		return -ENOMEM;

	state->clients = clients;

	for (size_t i = 0; i < nn; i++) {
		reset_client_state(&clients[i], i);
		ret = mutex_init(&clients[i].lock, NULL);
		if (unlikely(ret)) {
			pr_err("mutex_init(&clients[%zu].lock), NULL): " PRERF,
			       i, PREAR(ret));
			return -ret;
		}
	}

	arr = calloc_wrp(nn, sizeof(*arr));
	if (unlikely(!arr))
		return -ENOMEM;

	ret = mutex_init(&cl_stk->lock, NULL);
	if (unlikely(ret)) {
		pr_err("mutex_init(&cl_stk->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}


	cl_stk->sp = (uint16_t)nn;
	cl_stk->max_sp = (uint16_t)nn;
	cl_stk->arr = arr;

#ifdef NDEBUG
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
			TASSERT((uint16_t)ret == (uint16_t)i);
		}

		/*
		 * Push full stack.
		 */
		for (size_t i = 0; i < 100; i++) {
			ret = clstk_push(cl_stk, (uint16_t)i);
			__asm__ volatile("":"+r"(cl_stk)::"memory");
			TASSERT(ret == -1);
		}

		/*
		 * Pop stack.
		 */
		for (size_t i = nn; i--;) {
			ret = clstk_pop(cl_stk);
			__asm__ volatile("":"+r"(cl_stk)::"memory");
			TASSERT((uint16_t)ret == (uint16_t)i);
		}


		/*
		 * Pop empty stack.
		 */
		for (size_t i = 0; i < 100; i++) {
			ret = clstk_pop(cl_stk);
			__asm__ volatile("":"+r"(cl_stk)::"memory");
			TASSERT(ret == -1);
		}
	}
#endif


	for (size_t i = 0; i < nn; i++)
		clstk_push(cl_stk, (uint16_t)i);

	TASSERT(cl_stk->sp == 0);
	return 0;
}


static int init_state(struct srv_state *state)
{
	int ret = 0;
	struct srv_cfg *cfg = state->cfg;

	state->intr_sig         = -1;
	state->tcp_fd           = -1;
	state->tun_fds          = NULL;
	state->threads          = NULL;
	state->clients          = NULL;
	state->cl_stk.sp        = 0;
	state->cl_stk.max_sp    = 0;
	state->cl_stk.arr       = NULL;
	state->epoll_map        = NULL;
	state->thread_assignee  = 0u;
	state->stop_el          = false;
	atomic_store(&state->on_thread_c, 0);

	ret = validate_cfg(cfg);
	if (unlikely(ret))
		return ret;

	ret = init_tun_fds_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_epoll_map(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_clients(state);
	if (unlikely(ret))
		return ret;

	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	return ret;
}


static int epoll_add(int epl_fd, int fd, uint32_t events)
{
	int err;
	struct epoll_event event;

	/* Shut the valgrind up! */
	memset(&event, 0, sizeof(struct epoll_event));

	event.events  = events;
	event.data.fd = fd;
	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_ADD, fd, &event) < 0)) {
		err = errno;
		pr_err("epoll_ctl(EPOLL_CTL_ADD): " PRERF, PREAR(err));
		return -err;
	}
	return 0;
}


static int epoll_delete(int epl_fd, int fd)
{
	int err;

	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_DEL, fd, NULL) < 0)) {
		err = errno;
		pr_err("epoll_ctl(EPOLL_CTL_DEL): " PRERF, PREAR(err));
		return -1;
	}
	return 0;
}


static int init_epoll(int *epoll_fd_p)
{
	int ret;
	int epoll_fd;

	prl_notice(3, "Initializing epoll...");
	epoll_fd = epoll_create(255);
	if (unlikely(epoll_fd < 0)) {
		ret = errno;
		pr_err("epoll_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	*epoll_fd_p = epoll_fd;
	return 0;
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


static int register_client2(int cli_fd, int32_t ret_idx, char *src_ip,
			    uint16_t src_port, struct srv_state *state)
{
	int ret = 0;
	uint16_t th_idx;
	struct srv_thread *thread;
	uint16_t idx = (uint16_t)ret_idx;
	struct srv_client *client = &state->clients[idx];

	th_idx = state->thread_assignee++ % state->cfg->sys.thread;
	thread = &state->threads[th_idx];

	ret = epoll_add(thread->epoll_fd, cli_fd, EPL_IN_EVT);
	if (unlikely(ret))
		goto out;

	state->epoll_map[cli_fd] = idx + EPL_MAP_SHIFT;

	client->cli_fd   = cli_fd;
	client->src_port = src_port;
	sane_strncpy(client->src_ip, src_ip, sizeof(client->src_ip));
out:
	return ret;
}


static int register_client(int cli_fd, struct sockaddr_in *saddr,
			   struct srv_thread *thread)
{
	int ret = 0;
	int32_t idx;
	uint16_t src_port = 0;
	char src_ip[IPV4_L] = {0};
	struct srv_state *state = thread->state;
	struct client_stack *cl_stk = &state->cl_stk;

	if (unlikely(!inet_ntop(AF_INET, &saddr->sin_addr, src_ip,
				sizeof(src_ip)))) {
		ret = errno;
		pr_err("inet_ntop(): " PRERF, PREAR(ret));
		ret = -ret;
		goto out_close;
	}
	src_ip[sizeof(src_ip) - 1] = '\0';
	src_port = ntohs(saddr->sin_port);


	if ((uint32_t)cli_fd >= (EPL_MAP_SIZE - EPL_MAP_SHIFT - 1u)) {
		pr_err("Cannot accept connection from %s:%u because the "
		       "accepted fd is too big (%d)", src_ip, src_port, cli_fd);
		ret = -EAGAIN;
		goto out_close;
	}


	mutex_lock(&cl_stk->lock);
	idx = clstk_pop(cl_stk);
	mutex_unlock(&cl_stk->lock);
	if (unlikely(idx == -1)) {
		pr_err("Client slot is full, cannot accept connection from "
		       "%s:%u", src_ip, src_port);
		ret = -EAGAIN;
		goto out_close;
	}


	ret = register_client2(cli_fd, idx, src_ip, src_port, state);
	if (unlikely(ret)) {
		/*
		 * We need to push back this index,
		 * because this popped `idx` is not
		 * used at the moment.
		 */
		goto out_push;
	}


	prl_notice(0, "New connection from " PRWIU, W_IU(&state->clients[idx]));
	return ret;


out_push:
	mutex_lock(&cl_stk->lock);
	clstk_push(cl_stk, (uint16_t)idx);
	mutex_unlock(&cl_stk->lock);

out_close:
	prl_notice(0, "Closing connection from %s:%u (fd=%d)...", src_ip,
		   src_port, cli_fd);
	close(cli_fd);
	return ret;
}


static int do_accept(int tcp_fd, struct sockaddr_in *saddr,
		     struct srv_state *state)
{
	int ret;
	int cli_fd;
	socklen_t addrlen = sizeof(*saddr);

	memset(saddr, 0, sizeof(*saddr));
	cli_fd = accept(tcp_fd, (struct sockaddr *)saddr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		int err = errno;
		if (err != EAGAIN)
			pr_err("accept(): " PRERF, PREAR(err));
		return -err;
	}

	ret = socket_setup(cli_fd, state);
	if (unlikely(ret))
		return ret;

	return cli_fd;
}


static int handle_tcp_event(int tcp_fd, uint32_t revents,
			    struct srv_thread *thread)
{
	int cli_fd;
	struct sockaddr_in saddr;
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -ENETDOWN;

	cli_fd = do_accept(tcp_fd, &saddr, thread->state);
	if (unlikely(cli_fd < 0))
		return cli_fd;

	return register_client(cli_fd, &saddr, thread);
}


static int handle_tun_event(int tun_fd, uint32_t revents,
			    struct srv_thread *thread)
{
#if DO_BUSY_READ
	uint8_t busy_read_try = 0;
#endif
	ssize_t read_ret;
	struct srv_state *state;
	struct tsrv_pkt_iface_data *buff;
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -ENETDOWN;

#if DO_BUSY_READ
busy_read_label:
#endif

	state    = thread->state;
	buff     = &thread->spkt.iface_data;
	read_ret = read(tun_fd, buff, sizeof(*buff));

	if (unlikely(read_ret < 0)) {
		int err = errno;
		if (likely(err == EAGAIN))
			return 0;

		pr_err("read(tun_fd=%d): " PRERF, tun_fd, PREAR(err));
		state->stop_el = true;
		return -err;
	}

	if (unlikely(read_ret == 0))
		return 0;

	prl_notice(5, "Read %zd bytes from tun_fd (%d)", read_ret, tun_fd);

#if DO_BUSY_READ
	if (likely(busy_read_try++ < BUSY_READ_COUNT))
		goto busy_read_label;
#endif
	return 0;
}


static ssize_t do_recv(int cli_fd, struct srv_client *client)
{
	size_t recv_s;
	size_t recv_len;

	recv_s   = client->recv_s;
	recv_len = sizeof(client->raw_pkt) - recv_s;
	return recv(cli_fd, client->raw_pkt + recv_s, recv_len, 0);
}


static void close_client_event_conn(struct srv_client *client,
				    struct srv_thread *thread,
				    struct srv_state *state)
{
	uint16_t idx = client->idx;
	int cli_fd = client->cli_fd;
	struct client_stack *cl_stk = &state->cl_stk;

	prl_notice(0, "Closing connection from " PRWIU " (fd=%d)...",
		   W_IU(client), cli_fd);

	epoll_delete(thread->epoll_fd, cli_fd);
	close(cli_fd);

	reset_client_state(client, idx);
	mutex_lock(&cl_stk->lock);
	clstk_push(cl_stk, idx);
	mutex_unlock(&cl_stk->lock);
}


static enum clevt handle_clpkt_nop(struct tcli_pkt __maybe_unused *cpkt,
				   struct srv_thread __maybe_unused *thread,
				   struct srv_client __maybe_unused *client,
				   size_t __maybe_unused cdata_len)
{
	enum clevt ret = CLE_OK;
	return ret;
}


static bool version_compare(struct tcli_pkt_handshake *hs)
{
	uint32_t cmp_a, cmp_b;
	struct teavpn2_version *tmp;

	if (hs->has_min) {
		tmp = &hs->min;
		cmp_a  = ((uint32_t)tmp->ver << 16u);
		cmp_a |= ((uint32_t)tmp->patch_lvl << 8u);
		cmp_a |= ((uint32_t)tmp->sub_lvl << 0u);

		cmp_b  = (VERSION << 16u);
		cmp_b |= (PATCHLEVEL << 8u);
		cmp_b |= (SUBLEVEL << 0u);

		if (cmp_b < cmp_a)
			return false;
	}

	if (hs->has_max) {
		tmp = &hs->max;
		cmp_a  = ((uint32_t)tmp->ver << 16u);
		cmp_a |= ((uint32_t)tmp->patch_lvl << 8u);
		cmp_a |= ((uint32_t)tmp->sub_lvl << 0u);

		cmp_b  = (VERSION << 16u);
		cmp_b |= (PATCHLEVEL << 8u);
		cmp_b |= (SUBLEVEL << 0u);

		if (cmp_b > cmp_a)
			return false;
	}

	return true;
}


static ssize_t send_to_client(struct srv_thread __maybe_unused *thread,
			      struct srv_client *client,
			      const void *pkt, size_t len)
{
	ssize_t send_ret;
	int cli_fd = client->cli_fd;

	send_ret = send(cli_fd, pkt, len, 0);
	if (unlikely(send_ret < 0)) {
		int err = errno;
		if (err != EAGAIN)
			pr_err("send(): " PRERF, PREAR(err));
		return -err;
	}

	prl_notice(6, "send() to " PRWIU " %zd bytes (passed len = %zu bytes)",
		   W_IU(client), send_ret, len);
	return send_ret;
}


static bool acknowledge_handshake(struct srv_thread *thread,
				  struct srv_client *client,
				  bool need_encryption)
{
	ssize_t tmp_ret;
	size_t send_len;
	struct tsrv_pkt *spkt = &thread->spkt;
	struct tsrv_pkt_handshake *hs = &spkt->handshake;

	spkt->type    = TSRV_PKT_HANDSHAKE;
	spkt->pad_len = 0u;
	spkt->length  = sizeof(spkt->handshake);
	send_len      = TSRV_PKT_MIN_READ + sizeof(spkt->handshake);

	hs->need_encryption = need_encryption;
	hs->has_min         = 1u;
	hs->has_max         = 1u;

	hs->cur.ver         = VERSION;
	hs->cur.patch_lvl   = PATCHLEVEL;
	hs->cur.sub_lvl     = SUBLEVEL;
	memcpy(hs->cur.extra, EXTRAVERSION, sizeof(EXTRAVERSION));

	memcpy(&hs->min, &hs->cur, sizeof(hs->min));
	memcpy(&hs->max, &hs->cur, sizeof(hs->max));

	tmp_ret = send_to_client(thread, client, spkt, send_len);
	return ((size_t)tmp_ret == send_len);
}


static enum clevt handle_clpkt_handshake(struct tcli_pkt __maybe_unused *cpkt,
					 struct srv_thread *thread,
					 struct srv_client *client,
					 size_t cdata_len)
{
	if (client->is_auth)
		return CLE_OK;

	prl_notice(0, "Receiving handshake from " PRWIU, W_IU(client));
	if (cdata_len != sizeof(cpkt->handshake)) {
		prl_notice(0, "Invalid handshake data length from " PRWIU
			   " (got %zu, expected %zu)", W_IU(client), cdata_len,
			   sizeof(cpkt->handshake));
		goto out_close;
	}

	if (!version_compare(&cpkt->handshake)) {
		prl_notice(0, "Invalid handshake version from " PRWIU,
			   W_IU(client));
		goto out_close;
	}

	prl_notice(0, "Acknowledging handshake to " PRWIU, W_IU(client));
	if (acknowledge_handshake(thread, client,
				  cpkt->handshake.need_encryption))
		return CLE_OK;

out_close:
	return CLE_CLOSE;
}


static enum clevt handle_clpkt_iface_data(struct tcli_pkt __maybe_unused *cpkt,
					  struct srv_thread __maybe_unused *thread,
					  struct srv_client __maybe_unused *client,
					  size_t __maybe_unused cdata_len)
{
	enum clevt ret = CLE_OK;
	return ret;
}


static enum clevt handle_clpkt_reqsync(struct tcli_pkt __maybe_unused *cpkt,
				       struct srv_thread __maybe_unused *thread,
				       struct srv_client __maybe_unused *client,
				       size_t __maybe_unused cdata_len)
{
	enum clevt ret = CLE_OK;
	return ret;
}



static enum clevt handle_client_event3(struct tcli_pkt *cpkt,
				       struct srv_thread *thread,
				       struct srv_client *client,
				       size_t cdata_len)
{
	switch (cpkt->type) {
	case TCLI_PKT_NOP:
		return handle_clpkt_nop(cpkt, thread, client, cdata_len);
	case TCLI_PKT_HANDSHAKE:
		return handle_clpkt_handshake(cpkt, thread, client, cdata_len);
	case TCLI_PKT_IFACE_DATA:
		return handle_clpkt_iface_data(cpkt, thread, client, cdata_len);
	case TCLI_PKT_REQSYNC:
		return handle_clpkt_reqsync(cpkt, thread, client, cdata_len);
	case TCLI_PKT_CLOSE:
		return CLE_CLOSE;
	}

	/*
	 * Data corruption!
	 */
	return client->is_auth ? CLE_ERROR : CLE_CLOSE;
}


static enum clevt handle_client_event2(struct srv_thread *thread,
				       struct srv_client *client)
{
	enum clevt ret = CLE_OK;
	size_t recv_s = client->recv_s;
	char *raw_pkt = client->raw_pkt;
	struct tcli_pkt *cpkt = &client->cpkt;

	/*
	 * `fdata_len` means full data length.
	 * It it the expected length of `cpkt->raw_buf`
	 */
	size_t fdata_len;

	/*
	 * `cdata_len` means current received data length.
	 * It is how many bytes of `cpkt->raw_buf` has been received.
	 */
	size_t cdata_len;

	/*
	 * `fpkt_len` means full packed length.
	 * It is `TCLI_PKT_MIN_READ + cpkt->length`
	 */
	size_t fpkt_len;


again:
	if (unlikely(recv_s < TCLI_PKT_MIN_READ)) {
		/*
		 * We must have received `TCLI_PKT_MIN_READ`
		 * bytes before dereferencing these 3 things:
		 *   - cpkt->type
		 *   - cpkt->pad_len
		 *   - cpkt->length
		 *
		 * At this point we don't yet fulfill that 
		 * length.
		 *
		 * So, bail out!
		 */
		goto out;
	}


	fdata_len = cpkt->length;
	fpkt_len  = TCLI_PKT_MIN_READ + fdata_len;
	cdata_len = recv_s - TCLI_PKT_MIN_READ;

	if (unlikely(fdata_len > sizeof(cpkt->raw_buf))) {
		ret    = client->is_auth ? CLE_ERROR : CLE_CLOSE;
		recv_s = 0;
		goto out;
	}


	if (cdata_len < fdata_len) {
		/*
		 * We haven't fully received the data.
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}


	ret = handle_client_event3(cpkt, thread, client, cdata_len);
	if (unlikely(ret != CLE_OK))
		goto out;

	if (recv_s > fpkt_len) {
		/*
		 * We have extra packet on the tail.
		 *
		 * Must memmove to the front before
		 * we run out of buffer!
		 *
		 */
		size_t tail_len = recv_s - fpkt_len;
		memmove(raw_pkt, raw_pkt + fpkt_len, tail_len);
		recv_s = tail_len;
		goto again;
	}

	recv_s = 0;
out:
	client->recv_s = recv_s;
	return ret;
}


static int handle_client_event(uint16_t map_to, int cli_fd, uint32_t revents,
			       struct srv_thread *thread)
{
#if DO_BUSY_RECV
	uint8_t busy_recv_try = 0u;
#endif
	enum clevt ret;
	ssize_t recv_ret;
	struct srv_state *state = thread->state;
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	struct srv_client *client = &state->clients[map_to - EPL_MAP_SHIFT];


	if (unlikely(revents & err_mask))
		goto out_close;


#if DO_BUSY_RECV
do_busy_recv:
#endif

	recv_ret = do_recv(cli_fd, client);

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "recv() from " PRWIU " returned 0", W_IU(client));
		goto out_close;
	}

	if (unlikely(recv_ret < 0)) {
		int err = errno;
		if (unlikely(err != EAGAIN)) {
			pr_err("recv() from " PRWIU ": " PRERF, W_IU(client),
			       PREAR(err));
			goto out_close;
		}
		goto out;
	}

	prl_notice(6, "recv() from " PRWIU " %zd bytes", W_IU(client),
		   recv_ret);

	client->recv_s += (size_t)recv_ret;
	ret = handle_client_event2(thread, client);
	if (unlikely(ret == CLE_ERROR))
		goto out_err;
	if (unlikely(ret == CLE_CLOSE))
		goto out_close;


#if DO_BUSY_RECV
	if (likely(busy_recv_try++ < BUSY_RECV_COUNT))
		goto do_busy_recv;
#endif


out:
	return 0;


out_err:
	if (unlikely(client->err_count++ >= CLIENT_MAX_ERRC)) {
		pr_err("Client " PRWIU " has reached the max number of "
		       "errors, closing...", W_IU(client));
		goto out_close;
	}
	return 0;


out_close:
	close_client_event_conn(client, thread, state);
	return 0;
}


static int handle_event(struct epoll_event *event, struct srv_thread *thread)
{
	int ret = 0;
	int fd = event->data.fd;
	uint16_t map_to;
	uint32_t revents = event->events;

	map_to = thread->state->epoll_map[(size_t)fd];
	switch (map_to) {
	case EPL_MAP_TO_NOP:
		panic("Bug: unmapped file descriptor %d in handle_event()", fd);
		abort();
	case EPL_MAP_TO_TCP:
		ret = handle_tcp_event(fd, revents, thread);
		break;
	case EPL_MAP_TO_TUN:
		ret = handle_tun_event(fd, revents, thread);
		break;
	default:
		ret = handle_client_event(map_to, fd, revents, thread);
		break;
	}

	if (unlikely(ret == -EAGAIN))
		ret = 0;

	return ret;
}


static int do_epoll_wait(int epoll_fd, struct epoll_event events[EPL_WAIT_NUM],
			 struct srv_thread *thread)
{
	int ret;

	ret = epoll_wait(epoll_fd, events, EPL_WAIT_NUM, 1000);
	if (unlikely(!ret))
		return ret;

	if (unlikely(ret < 0)) {
		ret = errno;
		if (unlikely(ret != EINTR)) {
			pr_err("epoll_wait(): " PRERF, PREAR(ret));
			return -ret;
		}

		prl_notice(0, "Thread %u is interrupted!", thread->thread_idx);
		return 0;
	}

	return ret;
}


static int do_event_loop_routine(int epoll_fd,
				 struct epoll_event events[EPL_WAIT_NUM],
				 struct srv_thread *thread)
{

	int ret = do_epoll_wait(epoll_fd, events, thread);
	if (unlikely(ret < 0))
		return ret;

	for (int i = 0; i < ret; i++) {
		int tmp = handle_event(&events[i], thread);
		if (unlikely(tmp))
			return tmp;
	}
	return 0;
}


static void *run_sub_thread(void *_thread_p)
{
	int ret = 0;
	struct srv_thread *thread = _thread_p;
	int epoll_fd = thread->epoll_fd;
	struct srv_state *state = thread->state;
	struct epoll_event events[EPL_WAIT_NUM];

	TASSERT(thread->thread_idx != 0);

	atomic_store(&thread->is_on, true);
	atomic_fetch_add_explicit(&state->on_thread_c, 1, memory_order_acquire);
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread);
		if (unlikely(ret))
			break;
	}
	atomic_store(&thread->is_on, false);
	atomic_fetch_sub_explicit(&state->on_thread_c, 1, memory_order_acquire);

	return NULL;
}


static int run_main_thread(struct srv_thread *thread)
{
	int ret = 0;
	int epoll_fd = thread->epoll_fd;
	struct srv_state *state = thread->state;
	struct epoll_event events[EPL_WAIT_NUM];
	uint16_t thread_num = state->cfg->sys.thread;

	TASSERT(thread->thread_idx == 0);

	atomic_store(&thread->is_on, true);
	atomic_fetch_add_explicit(&state->on_thread_c, 1, memory_order_acquire);

	while (atomic_load_explicit(&state->on_thread_c,
				    memory_order_acquire) < thread_num)
		usleep(50000);

	prl_notice(0, "Initialization Sequence Completed");
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread);
		if (unlikely(ret))
			break;
	}
	atomic_store(&thread->is_on, false);
	atomic_fetch_sub_explicit(&state->on_thread_c, 1, memory_order_acquire);

	return ret;
}


static int run_workers(struct srv_state *state)
{
	size_t i;
	int ret = 0;
	int *tun_fds = state->tun_fds;
	size_t nn = state->cfg->sys.thread;
	struct srv_thread *thread, *threads = state->threads;

	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];

		thread = &threads[i];
		thread->epoll_fd = -1;

		ret = init_epoll(&thread->epoll_fd);
		if (unlikely(ret))
			goto out_err;

		ret = epoll_add(thread->epoll_fd, tun_fd, EPL_IN_EVT);
		if (unlikely(ret))
			goto out_err;

		/*
		 * Don't spawn thread for `i == 0`,
		 * because we are going to run it
		 * on the main thread.
		 */
		if (unlikely(i == 0))
			continue;

		pthread_create(&thread->thread, NULL, run_sub_thread, thread);
		pthread_detach(thread->thread);
	}


	thread = &threads[0];

	/*
	 * Main thread is responsible to accept
	 * new connections, so we add tcp_fd to
	 * its epoll monitoring resource.
	 */
	ret = epoll_add(thread->epoll_fd, state->tcp_fd, EPL_IN_EVT);
	if (unlikely(ret))
		goto out_err;

	return run_main_thread(thread);

out_err:
	state->stop_el = true;
	while (i--) {
		thread = &threads[i];
		close(thread->epoll_fd);
		thread->epoll_fd = -1;
		pthread_kill(thread->thread, SIGTERM);
	}
	return ret;
}


static void terminate_threads(struct srv_state *state)
{
	size_t nn = state->cfg->sys.thread;
	struct srv_thread *threads = state->threads;

	/*
	 * Don't kill main thread (i = 0)
	 */
	for (size_t i = 1; i < nn; i++) {
		struct srv_thread *thread = &threads[i];
		_Atomic(bool) *is_on = &thread->is_on;

		if (atomic_load_explicit(is_on, memory_order_acquire))
			pthread_kill(thread->thread, SIGTERM);
	}
}


static void wait_for_threads(struct srv_state *state)
{
	uint16_t ret;
	bool pr = false;
	_Atomic(uint16_t) *c = &state->on_thread_c;

	do {
		ret = atomic_load_explicit(c, memory_order_acquire);
		if (ret == 0)
			break;

		if (!pr) {
			pr = true;
			prl_notice(1, "Waiting for threads to exit...");
			terminate_threads(state);
		}

		usleep(100000);
	} while (true);
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


static void close_clients(struct srv_client *clients, size_t nn)
{
	if (!clients)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct srv_client *client = &clients[i];
		int cli_fd = client->cli_fd;

		mutex_destroy(&client->lock);
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
	mutex_destroy(&state->cl_stk.lock);
	free(state->cl_stk.arr);
	free(state->tun_fds);
	free(state->threads);
	free(state->clients);
	free(state->epoll_map);
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret;
	struct srv_state *state;

	state = malloc(sizeof(*state));
	if (unlikely(!state)) {
		pr_err("malloc(): Cannot allocate memory");
		return -ENOMEM;
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

	ret = run_workers(state);
out:
	wait_for_threads(state);
	destroy_state(state);
	free(state);
	return ret;
}

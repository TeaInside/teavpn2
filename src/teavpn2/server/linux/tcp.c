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

#include <teavpn2/tcp.h>
#include <teavpn2/lock.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

#include <bluetea/lib/string.h>

#define CALCULATE_STATS	1

#define EPL_MAP_SIZE	0x10000u
#define EPL_MAP_TO_NOP	0x00000u
#define EPL_MAP_TO_TCP	0x00001u
#define EPL_MAP_TO_TUN	0x00002u

#define EPL_MAP_SHIFT	0x00003u
#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI | EPOLLHUP)
#define EPL_WAIT_NUM	16

/* Macros for printing  */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->username)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


struct srv_thread {
	_Atomic(bool)			is_on;
	pthread_t			thread;
	struct srv_state		*state;
	int				epoll_fd;
	uint16_t			thread_num;
};


struct srv_client {
	bool				is_auth;
	int				cli_fd;
	char				username[255u];
	char				src_ip[IPV4_L];
	uint16_t			src_port;
	uint16_t			idx;
};


/*
 * We use stack to retrieve free index in
 * client slot array.
 */
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
	size_t				pkt_len;
	struct tsrv_pkt			pkt;
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
		threads[i].thread_num = (uint16_t)i;
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
	client->cli_fd        = -1;
	client->username[0]   = '_';
	client->username[1]   = '\0';
	client->idx           = (uint16_t)idx;
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

	for (size_t i = 0; i < nn; i++)
		reset_client_state(&clients[i], i);

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
	state->epoll_map        = NULL;
	state->clients          = NULL;
	state->stop_el          = false;
	state->cl_stk.arr       = NULL;
	state->thread_assignee  = 0u;
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
		pr_error("epoll_ctl(EPOLL_CTL_DEL): " PRERF, PREAR(err));
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
		if (unlikely(tmp_fd < 0)) {
			ret = tmp_fd;
			goto out_err;
		}

		ret = fd_set_nonblock(tmp_fd);
		if (unlikely(ret < 0)) {
			close(tmp_fd);
			goto out_err;
		}

		tun_fds[i] = tmp_fd;
		epoll_map[tmp_fd] = EPL_MAP_TO_TUN;
	}


	if (unlikely(!teavpn_iface_up(iff))) {
		pr_err("Cannot bring virtual network interface up");
		ret = -ENETDOWN;
		goto out_err;
	}


	return 0;

out_err:
	while (i--) {
		/*
		 * Several file descriptors may have been opened.
		 * Let's close it because we failed.
		 *
		 * It's our responsibility to close if we fail, not the caller!
		 */
		int fd = tun_fds[i];

		prl_notice(5, "Closing tun_fds[%zu] (%d)...", i, fd);
		epoll_map[fd] = EPL_MAP_TO_NOP;
		close(fd);
		tun_fds[i] = -1;
	}
	return ret;
}


static int socket_setup(int tcp_fd, struct srv_state *state)
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


	y = 1;
	ret = setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(ret < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}


	y = 6;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}


	y = 1024 * 1024 * 4;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}


	y = 50000;
	ret = setsockopt(tcp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


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
	ret = socket_setup(tcp_fd, state);
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


static int do_accept(int tcp_fd, struct sockaddr_in *saddr)
{
	int cli_fd;
	socklen_t addrlen = sizeof(*saddr);

	memset(saddr, 0, sizeof(*saddr));
	cli_fd = accept(tcp_fd, saddr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		int err = errno;
		if (err != EAGAIN)
			pr_err("accept(): " PRERF, PREAR(err));
		return -err;
	}

	return cli_fd;
}


static int assign_client(int cli_fd, int32_t ret_idx, char *src_ip,
			 uint16_t src_port, struct srv_state *state)
{
	int ret = 0;
	uint16_t idx = (uint16_t)ret_idx;
	struct srv_client *client = &state->clients[idx];
	struct srv_thread *thread;
	uint16_t th_idx;

	th_idx = state->thread_assignee++ % state->cfg->sys.thread;
	thread = &state->threads[th_idx];

	ret = epoll_add(thread->epoll_fd, cli_fd, EPL_IN_EVT);
	if (unlikely(ret))
		goto out;

	state->epoll_map[cli_fd] = idx + EPL_MAP_SHIFT;

	client->cli_fd      = cli_fd;
	client->src_port    = src_port;
	sane_strncpy(client->src_ip, src_ip, sizeof(client->src_ip));
out:
	return ret;
}


static int register_client(int cli_fd, struct sockaddr_in *saddr,
			   struct srv_state *state)
{
	int ret = 0;
	int32_t idx;
	char src_ip[IPV4_L] = {0};
	uint16_t src_port = 0;
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


	/*
	 * This file descriptor is too big to be mapped.
	 */
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

	ret = assign_client(cli_fd, idx, src_ip, src_port, state);
	if (unlikely(ret))
		goto out_push;

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


static int handle_tcp_event(uint32_t revents, struct srv_state *state)
{
	int cli_fd;
	struct sockaddr_in saddr;
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -ENETDOWN;

	cli_fd = do_accept(state->tcp_fd, &saddr);
	if (unlikely(cli_fd < 0))
		return cli_fd;

	return register_client(cli_fd, &saddr, state);
}


static int handle_tun_event(int tun_fd, uint32_t revents,
			    struct srv_state *state)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	ssize_t read_ret;
	struct tsrv_pkt_iface_data *buff = &state->pkt.iface_data;

	if (unlikely(revents & err_mask))
		return -ENETDOWN;

	read_ret = read(tun_fd, buff, sizeof(*buff));
	if (unlikely(read_ret < 0)) {
		int err = errno;
		if (err == EAGAIN)
			return 0;

		pr_err("read(tun_fd=%d): " PRERF, tun_fd, PREAR(err));
		state->stop_el = true;
		return -err;
	}


	if (unlikely(read_ret == 0))
		return 0;

	prl_notice(5, "Read %zd bytes from tun_fd (%d)", read_ret, tun_fd);

	return 0;
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


static int handle_client_event(int fd, uint16_t map_to, uint32_t revents,
			       struct srv_thread *thread,
			       struct srv_state *state)
{
	ssize_t recv_ret;
	char buff[2048];
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	struct srv_client *client = &state->clients[map_to - EPL_MAP_SHIFT];

	if (unlikely(revents & err_mask))
		goto out_close;


	recv_ret = recv(fd, buff, sizeof(buff), 0);
	if (unlikely(recv_ret == 0))
		goto out_close;

	prl_notice(0, "recv_ret = %zd", recv_ret);

	return 0;

out_close:
	close_client_event_conn(client, thread, state);
	return 0;
}


static int handle_event(struct epoll_event *event, struct srv_thread *thread,
			struct srv_state *state)
{
	int ret = 0;
	int fd = event->data.fd;
	uint16_t map_to;
	uint32_t revents = event->events;

	map_to = state->epoll_map[(size_t)fd];
	switch (map_to) {
	case EPL_MAP_TO_NOP:
		panic("Bug: unmapped file descriptor %d in handle_event()", fd);
		abort();
	case EPL_MAP_TO_TCP:
		ret = handle_tcp_event(revents, state);
		break;
	case EPL_MAP_TO_TUN:
		ret = handle_tun_event(fd, revents, state);
		break;
	default:
		ret = handle_client_event(fd, map_to, revents, thread, state);
		break;
	}

	if (unlikely(ret == -EAGAIN))
		ret = 0;

	return ret;
}


static int do_epoll_wait(int epoll_fd, struct epoll_event events[EPL_WAIT_NUM])
{
	int ret;

	ret = epoll_wait(epoll_fd, events, EPL_WAIT_NUM, 1000);
	if (unlikely(!ret)) {
		// prl_notice(5, "epoll_wait() reached its timeout");
		return ret;
	}

	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret == EINTR) {
			prl_notice(0, "Interrupted!");
			return 0;
		}

		pr_err("epoll_wait(): " PRERF, PREAR(ret));
		return -ret;
	}

	return ret;
}


static int do_event_loop_routine(int epoll_fd,
				 struct epoll_event events[EPL_WAIT_NUM],
				 struct srv_thread *thread,
				 struct srv_state *state)
{
	int ret = do_epoll_wait(epoll_fd, events);
	if (unlikely(ret < 0))
		return ret;

	for (int i = 0; i < ret; i++) {
		int tmp = handle_event(&events[i], thread, state);
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

	TASSERT(thread->thread_num != 0);

	atomic_store(&thread->is_on, true);
	atomic_fetch_add_explicit(&state->on_thread_c, 1, memory_order_acquire);
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread, state);
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

	TASSERT(thread->thread_num == 0);

	atomic_store(&thread->is_on, true);
	atomic_fetch_add_explicit(&state->on_thread_c, 1, memory_order_acquire);

	while (atomic_load_explicit(&state->on_thread_c,
				    memory_order_acquire) < thread_num)
		usleep(50000);

	prl_notice(0, "Initialization Sequence Completed");
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread, state);
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
	struct srv_thread *thread, *threads = state->threads;

	/*
	 * Don't kill main thread (i = 0)
	 */
	for (size_t i = 1; i < nn; i++) {
		thread = &threads[i];
		if (atomic_load_explicit(&thread->is_on,
					 memory_order_acquire)) {
			pthread_kill(thread->thread, SIGTERM);
		}
	}
}


static void wait_for_threads(struct srv_state *state)
{
	uint16_t ret;
	bool pr = false;

	do {
		ret = atomic_load_explicit(&state->on_thread_c,
					   memory_order_acquire);

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

		prl_notice(3, "Closing state->tun_fds[%zu] (%d)...", i,
			   tun_fds[i]);
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

		prl_notice(3, "Closing state->threads[%zu].epoll_fd (%d)...",
			   i, epoll_fd);
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

		if (cli_fd == -1)
			continue;

		prl_notice(3, "Closing state->clients[%zu].cli_fd (%d)...",
			   i, cli_fd);
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

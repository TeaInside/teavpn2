// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TeaVPN2 server core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/ip.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>

#include <teavpn2/tcp_pkt.h>
#include <teavpn2/allocator.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>

#include <bluetea/lib/mutex.h>
#include <bluetea/lib/string.h>

/*
 * See: https://github.com/axboe/liburing/issues/366
 */
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#  pragma clang diagnostic ignored "-Wshorten-64-to-32"
#  pragma clang diagnostic ignored "-Wsign-conversion"
#endif
#include <liburing.h>
#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

#define EPL_MAP_SIZE		0x10000u
#define EPL_MAP_TO_NOP		0x00000u
#define EPL_MAP_TO_TCP		0x00001u
#define EPL_MAP_TO_TUN		0x00002u
#define EPL_MAP_SHIFT		0x00003u
#define EPL_IN_EVT		(EPOLLIN | EPOLLPRI | EPOLLHUP)
#define EPL_WAIT_ARRSIZ		16
#define CLIENT_MAX_ERRC		20u

#define RING_QUE_NOP		(1u << 0u)
#define RING_QUE_TUN		(1u << 1u)
#define RING_QUE_TCP		(1u << 2u)
#define RING_QUE_CLIENT		(1u << 3u)

/* Macros for printing  */
#define W_IP(CLIENT) 		((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) 		((CLIENT)->username)
#define W_IU(CLIENT) 		W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU 			"%s:%d (%s)"

struct ring_queue {
	uint32_t			type;
	uint32_t			idx;
	union {
		int			fd;
		void			*ptr;
	};
};


struct srv_thread {
	_Atomic(bool)			is_online;
	bool				ring_init;
	pthread_t			thread;
	struct srv_state		*state;
	struct io_uring			ring;
	int				tun_fd;

	/* `idx` is the index where it's stored in the thread array. */
	uint16_t			idx;

	/* `read_s` is the valid bytes in the below union buffer. */
	size_t				read_s;

	alignas(64) union {
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
	char				src_ip[IPV4_L + 1u];
	uint16_t			src_port;

	/* `idx` is the index where it's stored in the client slot array. */
	uint16_t			idx;

	uint16_t			err_count;

	/* `recv_s` is the valid bytes in the below union buffer. */
	size_t				recv_s;

	alignas(64) union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};

	struct bt_mutex			lock;
};


struct srv_stack {
	struct bt_mutex			lock;
	uint16_t			*arr;
	uint16_t			sp;
	uint16_t			max_sp;
};


struct accept_data {
	int				acc_fd;
	socklen_t			addrlen;
	struct sockaddr_in		addr;
};


struct srv_state {
	int				intr_sig;
	int				tcp_fd;
	uint32_t			ring_que_c;
	int				*tun_fds;
	struct ring_queue		*ring_que;

	/* Client slot array */
	struct client_slot		*clients;

	/* Thread array */
	struct srv_thread		*threads;

	struct srv_cfg			*cfg;
	_Atomic(uint32_t)		tr_assign;
	_Atomic(uint32_t)		online_tr;
	struct accept_data		acc;
	struct srv_stack		cl_stk;
	struct srv_stack		rq_stk;
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
		return;
	}

	panic("Bug: handle_interrupt is called when g_state is NULL\n");
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
	void *ret;

	ret = al64_calloc(nmemb, size);
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

	for (size_t i = 0; i < nn; i++) {
		int ret;
		reset_client_state(&clients[i], i);

		if ((ret = bt_mutex_init(&clients[i].lock, NULL)))
			panic("bt_mutex_init(): " PRERF, PREAR(ret));
	}

	state->clients = clients;
	return 0;
}


static int init_state_ring_queue_array(struct srv_state *state)
{
	struct ring_queue *ring_que, *que;
	size_t nn = state->ring_que_c;

	ring_que = calloc_wrp(nn, sizeof(*ring_que));
	if (unlikely(!ring_que))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++) {
		que = &ring_que[i];
		que->type = RING_QUE_NOP;
		que->idx  = (uint32_t)i;
		que->ptr  = NULL;
	}

	state->ring_que = ring_que;
	return 0;
}


static int init_state_threads(struct srv_state *state)
{
	struct srv_thread *threads, *thread;
	struct srv_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	threads = calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++) {
		thread = &threads[i];
		thread->idx   = (uint16_t)i;
		thread->state = state;
	}

	state->threads = threads;
	return 0;
}


static int32_t srstk_push(struct srv_stack *cl_stk, uint16_t idx)
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


static int32_t srstk_pop(struct srv_stack *cl_stk)
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
	int32_t ret;
	uint16_t *arr;
	size_t nn = state->cfg->sock.max_conn;
	struct srv_stack *cl_stk = &state->cl_stk;

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
	/*
	 * Push stack.
	 */
	for (size_t i = 0; i < nn; i++) {
		ret = srstk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}

	/*
	 * Push full stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srstk_push(cl_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}

	/*
	 * Pop stack.
	 */
	for (size_t i = nn; i--;) {
		ret = srstk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}


	/*
	 * Pop empty stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srstk_pop(cl_stk);
		__asm__ volatile("":"+r"(cl_stk)::"memory");
		BT_ASSERT(ret == -1);
	}
}
#endif
	while (nn--)
		srstk_push(cl_stk, (uint16_t)nn);

	BT_ASSERT(cl_stk->sp == 0);
	return 0;
}


static int init_state_ring_queue_stack(struct srv_state *state)
{
	int32_t ret;
	uint16_t *arr;
	size_t nn = state->ring_que_c;
	struct srv_stack *rq_stk = &state->rq_stk;

	arr = calloc_wrp(nn, sizeof(*arr));
	if (unlikely(!arr))
		return -ENOMEM;

	ret = bt_mutex_init(&rq_stk->lock, NULL);
	if (unlikely(ret)) {
		pr_err("mutex_init(&rq_stk->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}

	rq_stk->sp = (uint16_t)nn;
	rq_stk->max_sp = (uint16_t)nn;
	rq_stk->arr = arr;

#ifndef NDEBUG
/*
 * Test only.
 */
{
	/*
	 * Push stack.
	 */
	for (size_t i = 0; i < nn; i++) {
		ret = srstk_push(rq_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(rq_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}

	/*
	 * Push full stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srstk_push(rq_stk, (uint16_t)i);
		__asm__ volatile("":"+r"(rq_stk)::"memory");
		BT_ASSERT(ret == -1);
	}

	/*
	 * Pop stack.
	 */
	for (size_t i = nn; i--;) {
		ret = srstk_pop(rq_stk);
		__asm__ volatile("":"+r"(rq_stk)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}


	/*
	 * Pop empty stack.
	 */
	for (size_t i = 0; i < 100; i++) {
		ret = srstk_pop(rq_stk);
		__asm__ volatile("":"+r"(rq_stk)::"memory");
		BT_ASSERT(ret == -1);
	}
}
#endif
	while (nn--)
		srstk_push(rq_stk, (uint16_t)nn);

	BT_ASSERT(rq_stk->sp == 0);
	return 0;

}


static int init_state(struct srv_state *state)
{
	int ret;

	state->intr_sig    = -1;
	state->tcp_fd      = -1;
	state->tun_fds     = NULL;
	state->clients     = NULL;
	state->stop        = false;
	atomic_store(&state->tr_assign, 0);
	atomic_store(&state->online_tr, 0);

	state->ring_que_c = state->cfg->sock.max_conn + 10u;

	ret = validate_cfg(state->cfg);
	if (unlikely(ret))
		return ret;

	ret = init_state_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_client_slot_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_ring_queue_array(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_threads(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_client_stack(state);
	if (unlikely(ret))
		return ret;

	ret = init_state_ring_queue_stack(state);
	if (unlikely(ret))
		return ret;

	signal(SIGINT, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);
	return ret;
}


static __no_inline int socket_setup(int cli_fd, struct srv_state *state)
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
	struct if_info *iff = &state->cfg->iface;

	prl_notice(3, "Allocating virtual network interface...");
	for (i = 0; i < nn; i++) {
		int tmp_fd;
		const short tun_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

		prl_notice(5, "Allocating TUN fd %zu...", i);
		tmp_fd = tun_alloc(iff->dev, tun_flags);
		if (unlikely(tmp_fd < 0))
			return tmp_fd;

		tun_fds[i] = tmp_fd;
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
	tcp_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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

	state->tcp_fd = tcp_fd;
	pr_notice("Listening on %s:%d...", sock->bind_addr, sock->bind_port);

	return 0;
out_err:
	close(tcp_fd);
	return -ret;
}


static int add_ring_poll(struct io_uring *ring, int fd, int32_t poll_mask,
			 void *user_data)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe)) {
		pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
		return -ENOMEM;
	}
	io_uring_prep_poll_add(sqe, fd, poll_mask);
	io_uring_sqe_set_data(sqe, (void *)(uintptr_t)user_data);
	return 0;
}


static struct ring_queue *get_ring_queue(struct srv_state *state)
{
	int32_t idx;
	bt_mutex_lock(&state->rq_stk.lock);
	idx = srstk_pop(&state->rq_stk);
	bt_mutex_unlock(&state->rq_stk.lock);
	if (unlikely(idx == -1))
		return NULL;

	return &state->ring_que[idx];
}


static struct ring_queue *put_ring_queue(struct srv_state *state,
					 struct ring_queue *que)
{
	int32_t idx;
	bt_mutex_lock(&state->rq_stk.lock);
	idx = srstk_push(&state->rq_stk, que->idx);
	bt_mutex_unlock(&state->rq_stk.lock);
	if (unlikely(idx == -1))
		panic("Stack overflow on put_ring_queue()");

	return &state->ring_que[idx];
}


static int do_uring_wait(struct io_uring *ring, struct io_uring_cqe **cqe)
{
	int ret;
	struct __kernel_timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 1000000000
	};


	ret = io_uring_wait_cqe_timeout(ring, cqe, &ts);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME))
		return ret;

	if (unlikely(ret == -EINTR)) {
		pr_notice("Interrupted!");
		return 0;
	}

	pr_err("io_uring_wait_cqe(): " PRERF, PREAR(-ret));
	return -ret;
}


static int handle_tun_event(struct srv_thread *thread, struct io_uring_cqe *cqe,
			    struct ring_queue *rq)
{
	int ret = 0;
	pr_debug("TUN = %d", cqe->res);
	io_uring_cqe_seen(&thread->ring, cqe);
	return 0;
}


static int __register_client(struct srv_thread *thread, int32_t idx, int cli_fd,
			     const char *src_ip, uint16_t src_port)
{
	int ret = 0;
	struct io_uring_sqe *sqe;
	struct client_slot *client;
	struct ring_queue *rq = NULL;
	struct srv_thread *picked = NULL;
	struct srv_state *state = thread->state;
	size_t num_threads = state->cfg->sys.thread;
	uint16_t th_idx = 0; /* Thread index (the assignee). */


	if (unlikely(num_threads <= 1)) {
		/*
		 * We are single threaded.
		 */
		picked = thread;
		rq = get_ring_queue(state);
		goto out_reg;
	}



	for (size_t i = 0; i < (num_threads + 1u); i++) {
		/*
		 * We are multi threaded.
		 */
		_Atomic(uint32_t) *tr_as = &state->tr_assign;

		th_idx = atomic_fetch_add(tr_as, 1) % state->cfg->sys.thread;
		picked = &state->threads[th_idx];

		/*
		 * Try to get possible ring queue.
		 *
		 * TODO: Separate ring queue per thread.
		 */
		rq = get_ring_queue(state);
		if (unlikely(!rq))
			continue;

		break;
	}


out_reg:
	if (unlikely(!rq)) {
		pr_err("Cannot get ring queue on __register_client()");
		return -EAGAIN;
	}


	sqe = io_uring_get_sqe(&picked->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring_get_sqe() run out of sqe");
		__builtin_unreachable();
	}


	io_uring_prep_recv(sqe, cli_fd, client->raw_pkt,
			   sizeof(client->raw_pkt), MSG_WAITALL);


	client   = &state->clients[idx];
	rq->type = RING_QUE_CLIENT;
	rq->ptr  = client;
	io_uring_sqe_set_data(sqe, rq);

	ret = io_uring_submit(&picked->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR((int)-ret));
		goto out;
	}


	ret = 0;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;
	sane_strncpy(client->src_ip, src_ip, sizeof(client->src_ip));

	prl_notice(0, "New connection from " PRWIU " (fd=%d) (thread=%u)",
		   W_IU(client), cli_fd, th_idx);
out:
	return ret;
}


static int register_client(struct srv_thread *__restrict__ thread, int cli_fd)
{
	int ret = 0;
	int32_t idx;
	uint16_t src_port = 0;
	char src_ip[IPV4_L] = {0};
	struct srv_state *state = thread->state;

	/*
	 * The remote IP and port in big-endian representation.
	 */
	struct sockaddr_in *saddr = &state->acc.addr;
	struct in_addr *sin_addr = &saddr->sin_addr;


	if (unlikely(!inet_ntop(AF_INET, sin_addr, src_ip, sizeof(src_ip)))) {
		ret = errno;
		pr_err("inet_ntop(): " PRERF, PREAR(ret));
		ret = -ret;
		goto out_close;
	}
	src_ip[sizeof(src_ip) - 1] = '\0';
	src_port = ntohs(saddr->sin_port);



	bt_mutex_lock(&state->cl_stk.lock);
	idx = srstk_pop(&state->cl_stk);
	bt_mutex_unlock(&state->cl_stk.lock);
	if (unlikely(idx == -1)) {
		pr_err("Client slot is full, cannot accept connection from "
		       "%s:%u", src_ip, src_port);
		ret = -EAGAIN;
		goto out_close;
	}


	ret = __register_client(thread, idx, cli_fd, src_ip, src_port);
	if (unlikely(ret)) {
		/*
		 * We need to push back this index,
		 * because this popped `idx` is not
		 * used at the moment.
		 */
		goto out_push;
	}
	return 0;


out_push:
	bt_mutex_lock(&state->cl_stk.lock);
	srstk_push(&state->cl_stk, (uint16_t)idx);
	bt_mutex_unlock(&state->cl_stk.lock);


out_close:
	pr_notice("Closing connection from %s:%u (fd=%d) (thread=%u) Error: "
		  PRERF "...", src_ip, src_port, cli_fd, thread->idx,
		  PREAR(-ret));
	close(cli_fd);
	return ret;
}


static int handle_tcp_event(struct srv_thread *thread, struct io_uring_cqe *cqe,
			    struct ring_queue *rq)
{
	int ret = 0, cli_fd;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_state *state = thread->state;

	put_ring_queue(state, rq);
	io_uring_cqe_seen(&thread->ring, cqe);

	cli_fd = cqe->res;
	if (unlikely(cli_fd < 0)) {
		ret = cli_fd;
		goto out_err;
	}

	ret = register_client(thread, cli_fd);
	goto out;


out_err:
	if (unlikely(ret == -EAGAIN))
		goto out_rearm;

	/*
	 * Fatal error, stop everything!
	 */
	pr_err("accpet(): " PRERF, PREAR(-ret));
	state->stop = true;
	return ret;


out_rearm:
	rq = get_ring_queue(state);
	if (unlikely(!rq)) {
		pr_emerg("Impossible happened!");
		panic("get_ring_queue() run out of queue");
		__builtin_unreachable();
	}


	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring_get_sqe() run out of sqe");
		__builtin_unreachable();
	}


	acc          = &state->acc;
	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	io_uring_prep_accept(sqe, state->tcp_fd, (struct sockaddr *)&acc->addr,
			     &acc->addrlen, 0);

	rq->type = RING_QUE_TCP;
	rq->fd   = state->tcp_fd;
	io_uring_sqe_set_data(sqe, rq);
out:
	return ret;
}


static int handle_event(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0;
	struct ring_queue *rq;

	rq = io_uring_cqe_get_data(cqe);
	if (unlikely(!rq))
		goto invalid_cqe;


	switch (rq->type) {
	case RING_QUE_TUN:
		ret = handle_tun_event(thread, cqe, rq);
		break;
	case RING_QUE_TCP:
		ret = handle_tcp_event(thread, cqe, rq);
		break;
	case RING_QUE_CLIENT:
		pr_debug("CLI = %d", cqe->res);
		break;
	default:
		pr_emerg("Invalid rq->type");
		goto invalid_cqe;
	}

	if (unlikely(ret == -EAGAIN))
		ret = 0;

	return ret;

invalid_cqe:
	pr_emerg("Invalid CQE on handle_event()");
	VT_HEXDUMP(cqe, sizeof(*cqe));
	panic("Invalid CQE!");
	__builtin_unreachable();
}


static int thread_wait(struct srv_state *state, size_t tr_num)
{

	return 0;
}


static int wait_for_threads_to_be_ready(struct srv_state *state, bool is_main)
{
	size_t tr_num = state->cfg->sys.thread;

	if (tr_num == 1)
		/* 
		 * Don't wait, we are single threaded.
		 */
		return 0;


	if (is_main) {

		pr_notice("Waiting for threads to be ready...");
		while (likely(atomic_load(&state->online_tr) < tr_num)) {
			if (unlikely(state->stop))
				return -EINTR;
			usleep(50000);
		}
		pr_notice("Threads are all ready!");
		pr_notice("Initialization Sequence Completed");
		return 0;

	} else {

		struct srv_thread *mt = &state->threads[0];
		while (likely(!atomic_load(&mt->is_online))) {
			if (unlikely(state->stop))
				return -EINTR;
			usleep(50000);
		}
		return -EALREADY;

	}
}


static __no_inline void *run_thread(void *_thread)
{
	intptr_t ret = 0;
	struct io_uring_cqe *cqe;
	struct srv_thread *thread = _thread;
	struct io_uring *ring = &thread->ring;
	struct srv_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	wait_for_threads_to_be_ready(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {

		ret = io_uring_submit(ring);
		if (unlikely(ret < 0)) {
			pr_err("io_uring_submit(): " PRERF, PREAR((int)-ret));
			break;
		}

		cqe = NULL;
		ret = do_uring_wait(ring, &cqe);
		if (unlikely(ret == -ETIME))
			continue;

		if (unlikely(ret))
			break;

		if (unlikely(!cqe))
			continue;

		ret = handle_event(thread, cqe);
		if (unlikely(ret))
			break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	return (void *)ret;
}


static int spawn_threads(struct srv_state *state)
{
	size_t i;
	unsigned en_num; /* Number of queue entries */
	struct io_uring_sqe *sqe;
	size_t nn = state->cfg->sys.thread;
	int ret = 0, *tun_fds = state->tun_fds;
	struct srv_thread *threads = state->threads;


	/*
	 * Distribute tun_fds to all threads. So each thread has
	 * its own tun_fds for writing.
	 */
	en_num = state->cfg->sock.max_conn + state->cfg->sys.thread + 3u;
	for (i = 0; i < nn; i++) {
		struct ring_queue *rq;
		int tun_fd = tun_fds[i];
		struct srv_thread *thread = &threads[i];
		struct io_uring *ring = &thread->ring;

		/*
		 * Each thread has its own io_uring instance.
		 */
		ret = io_uring_queue_init(en_num, ring, 0);
		if (unlikely(ret)) {
			pr_err("io_uring_queue_init(): " PRERF, PREAR(-ret));
			break;
		}
		thread->ring_init = true;

		rq = get_ring_queue(state);
		if (unlikely(!rq)) {
			pr_err("get_ring_queue(): " PRERF, PREAR(EAGAIN));
			ret = -EAGAIN;
			break;
		}

		sqe = io_uring_get_sqe(ring);
		if (unlikely(!sqe)) {
			pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
			ret = -ENOMEM;
			break;
		}

		io_uring_prep_read(sqe, tun_fd, thread->raw_pkt,
				   sizeof(thread->raw_pkt), 0);

		rq->type = RING_QUE_TUN;
		rq->fd   = tun_fd;
		io_uring_sqe_set_data(sqe, rq);


		/*
		 * Don't spawn a thread for `i == 0`,
		 * because we are going to run it on
		 * the main thread.
		 */
		if (unlikely(i == 0))
			continue;


		ret = pthread_create(&thread->thread, NULL, run_thread, thread);
		if (unlikely(ret)) {
			pr_err("pthread_create(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}


		ret = pthread_detach(thread->thread);
		if (unlikely(ret)) {
			pr_err("pthread_detach(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}
	}


	return ret;
}


static int run_workers(struct srv_state *state)
{
	int ret = 0;
	struct ring_queue *rq;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_thread *thread;

	ret = spawn_threads(state);
	if (unlikely(ret))
		goto out;

	/*
	 * Main thread is responsible to accept
	 * new connections, so we add tcp_fd to
	 * its uring queue resource.
	 */
	acc    = &state->acc;
	thread = &state->threads[0];
	rq = get_ring_queue(state);
	if (unlikely(!rq)) {
		pr_err("get_ring_queue(): " PRERF, PREAR(EAGAIN));
		ret = -EAGAIN;
		goto out;
	}

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
		ret = -ENOMEM;
		goto out;
	}

	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	io_uring_prep_accept(sqe, state->tcp_fd, (struct sockaddr *)&acc->addr,
			     &acc->addrlen, 0);

	rq->type = RING_QUE_TCP;
	rq->fd   = state->tcp_fd;
	io_uring_sqe_set_data(sqe, rq);

	/*
	 * Run the main thread!
	 */
	ret = (int)((intptr_t)run_thread(thread));
out:
	return ret;
}


static void wait_for_threads(struct srv_state *state)
{

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


static void close_threads(struct srv_thread *threads, size_t nn)
{
	if (!threads)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct srv_thread *thread = &threads[i];
		if (thread->ring_init)
			io_uring_queue_exit(&thread->ring);
	}
}


static void close_clients(struct client_slot *clients, size_t nn)
{
	if (!clients)
		return;

	for (size_t i = 0; i < nn; i++) {
		struct client_slot *client = &clients[i];
		int cli_fd = client->cli_fd;

		bt_mutex_destroy(&client->lock);
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
	close_clients(state->clients, state->cfg->sock.max_conn);
}


static void destroy_state(struct srv_state *state)
{
	close_fds(state);
	close_threads(state->threads, state->cfg->sys.thread);
	bt_mutex_destroy(&state->cl_stk.lock);
	bt_mutex_destroy(&state->rq_stk.lock);
	al64_free(state->cl_stk.arr);
	al64_free(state->rq_stk.arr);
	al64_free(state->ring_que);
	al64_free(state->tun_fds);
	al64_free(state->threads);
	al64_free(state->clients);
}


int teavpn2_server_tcp(struct srv_cfg *cfg)
{
	int ret = 0;
	struct srv_state *state;

	state = al64_malloc(sizeof(*state));
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

	ret = run_workers(state);
out:
	wait_for_threads(state);
	destroy_state(state);
	al64_free(state);
	return ret;
}

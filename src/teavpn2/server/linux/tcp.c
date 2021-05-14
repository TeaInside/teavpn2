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

#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>


#define CALCULATE_STATS	1

#define EPL_MAP_SIZE	0x10000u
#define EPL_MAP_TO_NOP	0x00000u
#define EPL_MAP_TO_TCP	0x00001u
#define EPL_MAP_TO_TUN	0x00002u

#define EPL_MAP_SHIFT	0x00003u
#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)
#define EPL_WAIT_NUM	16


struct srv_thread {
	pthread_t		thread;
	struct srv_state	*state;
	int			epoll_fd;
	uint16_t		thread_num;
};


struct srv_client {
	int			cli_fd;
	bool			is_auth;
};


struct srv_state {
	int			intr_sig;
	int			tcp_fd;
	int			*tun_fds;
	struct srv_thread	*threads;
	struct srv_client	*clients;
	struct srv_cfg 		*cfg;
	uint16_t		*epoll_map;
	bool			stop_el;
};


static struct srv_state *g_state = NULL;


static void handle_interrupt(int sig)
{
	struct srv_state *state = g_state;

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


static int init_state(struct srv_state *state)
{
	int ret = 0;
	struct srv_cfg *cfg = state->cfg;

	state->intr_sig     = -1;
	state->tcp_fd       = -1;
	state->tun_fds      = NULL;
	state->threads      = NULL;
	state->epoll_map    = NULL;
	state->stop_el      = false;

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
		if (tmp_fd < 0) {
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


static int handle_tcp_event(uint32_t revents, struct srv_state *state)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	(void)revents;
	(void)state;
	(void)err_mask;
	return 0;
}


static int handle_tun_event(int fd, uint32_t revents, struct srv_state *state)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	ssize_t read_ret;
	char buffer[8192];

	read_ret = read(fd, buffer, sizeof(buffer));
	(void)revents;
	(void)state;
	(void)err_mask;
	return 0;
}


static int handle_client_event(uint16_t map_to, uint32_t revents,
			       struct srv_state *state)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;
	(void)map_to;
	(void)revents;
	(void)state;
	(void)err_mask;
	return 0;
}


static int handle_event(struct epoll_event *event, struct srv_state *state)
{
	int fd = event->data.fd;
	uint16_t map_to;
	uint32_t revents = event->events;

	map_to = state->epoll_map[(size_t)fd];
	switch (map_to) {
	case EPL_MAP_TO_NOP:
		panic("Bug: unmapped file descriptor %d in handle_event()", fd);
		abort();
	case EPL_MAP_TO_TCP:
		return handle_tcp_event(revents, state);
	case EPL_MAP_TO_TUN:
		return handle_tun_event(fd, revents, state);
	default:
		return handle_client_event(map_to, revents, state);
	}
}


static int do_epoll_wait(int epoll_fd, struct epoll_event events[EPL_WAIT_NUM])
{
	int ret;

	ret = epoll_wait(epoll_fd, events, EPL_WAIT_NUM, 5000);
	if (unlikely(!ret)) {
		prl_notice(5, "epoll_wait() reached its timeout");
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
		int tmp = handle_event(&events[i], state);
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
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread, state);
		if (unlikely(ret))
			break;
	}

	return NULL;
}


static int run_main_thread(struct srv_thread *thread)
{
	int ret = 0;
	int epoll_fd = thread->epoll_fd;
	struct srv_state *state = thread->state;
	struct epoll_event events[EPL_WAIT_NUM];

	TASSERT(thread->thread_num == 0);
	while (likely(!state->stop_el)) {
		ret = do_event_loop_routine(epoll_fd, events, thread, state);
		if (unlikely(ret))
			break;
	}

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
		if (i == 0)
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
	kill(getpid(), SIGTERM);
	while (i--) {
		thread = &threads[i];
		close(thread->epoll_fd);
		thread->epoll_fd = -1;
	}
	return ret;
}


static void close_fds(struct srv_state *state)
{
	int tcp_fd = state->tcp_fd;
	int *tun_fds = state->tun_fds;
	size_t nn = state->cfg->sys.thread;
	struct srv_thread *threads = state->threads;

	for (size_t i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;

		prl_notice(3, "Closing state->tun_fds[%zu] (%d)...", i,
			   tun_fds[i]);
		close(tun_fds[i]);
	}

	if (tcp_fd != -1) {
		prl_notice(3, "Closing state->tcp_fd (%d)...", tcp_fd);
		close(tcp_fd);
	}

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


static void destroy_state(struct srv_state *state)
{
	close_fds(state);
	free(state->tun_fds);
	free(state->threads);
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
	destroy_state(state);
	free(state);
	return ret;
}

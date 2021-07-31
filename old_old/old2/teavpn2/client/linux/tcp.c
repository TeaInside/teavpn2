// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp.c
 *
 *  TeaVPN2 client core for Linux.
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
#include <teavpn2/client/linux/tcp.h>

#include <bluetea/lib/string.h>

#define CALCULATE_STATS		1

#define EPL_MAP_SIZE		0x10000u
#define EPL_MAP_TO_NOP		0x00000u
#define EPL_MAP_TO_TCP		0x00001u
#define EPL_MAP_TO_TUN		0x00002u

#define EPL_MAP_SHIFT		0x00003u
#define EPL_IN_EVT		(EPOLLIN | EPOLLPRI | EPOLLHUP)
#define EPL_WAIT_NUM		4u

#define DO_BUSY_RECV		1
#define BUSY_RECV_COUNT		10
#define DO_BUSY_READ		1
#define BUSY_READ_COUNT		10

struct cli_thread {
	_Atomic(bool)			is_on;
	pthread_t			thread;
	struct cli_state		*state;
	int				epoll_fd;
	uint16_t			thread_idx;
};


struct cli_state {
	int				intr_sig;
	int				tcp_fd;
	int				*tun_fds;
	struct cli_thread		*threads;
	struct cli_cfg			*cfg;
	uint16_t			*epoll_map;

	bool				stop_el;
	bool				handshake_ok;
	bool				authenticated;
	_Atomic(uint16_t)		on_thread_c;
	size_t				pkt_len;
	union {
		struct tsrv_pkt		spkt;
		struct tcli_pkt		cpkt;
		char			raw_pkt[sizeof(struct tcli_pkt)];
	};
};


static struct cli_state *g_state = NULL;


static void handle_interrupt(int sig)
{
	struct cli_state *state = g_state;

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


static int validate_cfg(struct cli_cfg *cfg)
{
	if (!cfg->sys.thread) {
		pr_err("Number of thread cannot be zero");
		return -EINVAL;
	}

	if (!cfg->sock.server_addr || !*cfg->sock.server_addr) {
		pr_err("cfg->sock.server_addr cannot be empty");
		return -EINVAL;
	}

	if (!cfg->sock.server_port) {
		pr_err("cfg->sock.server_port cannot be zero");
		return -EINVAL;
	}

	if (!*cfg->iface.dev) {
		pr_err("cfg->iface.dev cannot be empty");
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


static int init_tun_fds_array(struct cli_state *state)
{
	int *tun_fds;
	struct cli_cfg *cfg = state->cfg;
	size_t nn = cfg->sys.thread;

	tun_fds = calloc_wrp(nn, sizeof(*tun_fds));
	if (unlikely(!tun_fds))
		return -ENOMEM;

	for (size_t i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int init_state_threads(struct cli_state *state)
{
	struct cli_thread *threads;
	struct cli_cfg *cfg = state->cfg;
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


static int init_state_epoll_map(struct cli_state *state)
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


static int init_state(struct cli_state *state)
{
	int ret = 0;
	struct cli_cfg *cfg = state->cfg;

	state->intr_sig         = -1;
	state->tcp_fd           = -1;
	state->tun_fds          = NULL;
	state->threads          = NULL;
	state->epoll_map        = NULL;
	state->handshake_ok     = false;
	state->authenticated    = false;
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

	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGHUP, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	return ret;
}


static int init_iface(struct cli_state *state)
{
	int ret;
	size_t i;
	int *tun_fds = state->tun_fds;
	size_t nn = state->cfg->sys.thread - 1;
	uint16_t *epoll_map = state->epoll_map;
	struct cli_iface_cfg *iff = &state->cfg->iface;

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

	return 0;
}


static int socket_setup(int tcp_fd, struct cli_state *state)
{
	int y;
	int err;
	int ret;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct cli_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;


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


static int init_tcp_socket(struct cli_state *state)
{
	int ret;
	int tcp_fd;
	struct sockaddr_in addr;
	struct cli_sock_cfg *sock = &state->cfg->sock;


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
	addr.sin_port = htons(sock->server_port);
	addr.sin_addr.s_addr = inet_addr(sock->server_addr);

	prl_notice(0, "Connecting to %s:%u...", sock->server_addr,
		   sock->server_port);
connect_again:
	ret = connect(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (likely(ret)) {
		ret = errno;
		if (likely((ret == EINPROGRESS) || (ret == EALREADY))) {
			usleep(5000);
			goto connect_again;
		}

		pr_error("connect(): " PRERF, PREAR(ret));
		goto out_err;
	}

	prl_notice(0, "Connection established!");
	state->epoll_map[tcp_fd] = EPL_MAP_TO_TCP;
	state->tcp_fd = tcp_fd;
	return 0;
out_err:
	close(tcp_fd);
	return -ret;
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



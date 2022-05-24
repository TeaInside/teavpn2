// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022  Ammar Faizi <ammarfaizi2@gmail.com>
 */
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <teavpn2/mutex.h>
#include <teavpn2/stack.h>
#include <teavpn2/packet.h>
#include <teavpn2/server/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/udp.h>

enum {
	EL_EPOLL,
	EL_IO_URING
};

struct udp_sess {
	_Atomic(bool)			is_authenticated;
	_Atomic(bool)			is_connected;
};

struct srv_state {
	/*
	 * To determine whether the event loop should stop.
	 */
	volatile bool			stop;

	/*
	 * Are we in an emergency situation?
	 * (currently unused)
	 */
	volatile bool			in_emergency;

	/*
	 * To determine whether we should remove the virtual
	 * network configuration on cleanup.
	 */
	bool				need_remove_iff;

	/*
	 * The event loop type. Currently, the only valid
	 * values are EL_EPOLL and EL_IO_URING.
	 */
	uint8_t				evt_loop_type;

	/*
	 * The number of online worker threads.
	 */
	_Atomic(uint16_t)		nr_on_threads;

	/*
	 * A pointer to the struct srv_cfg that contains
	 * TeaVPN2 server configuration.
	 */
	struct srv_cfg			*cfg;

	/*
	 * Array of UDP sessions.
	 */
	struct udp_sess			*sess;

	/*
	 * The file descriptor of the server UDP socket.
	 */
	int				udp_fd;

	/*
	 * Received signal from the signal handler.
	 */
	int				sig;

	/*
	 * The number of elements in the @tun_fds array.
	 *
	 * The number of elements in @tun_fds is currently
	 * the same with @cfg->sys.thread_num.
	 */
	uint16_t			nr_tun_fds;

	/*
	 * The array of file descriptors of the TUN interface.
	 */
	int				tun_fds[];
};

static DEFINE_MUTEX(g_state_mutex);
static struct srv_state *g_state = NULL;

static void signal_handler(int sig)
{
	struct srv_state *state;

	state = g_state;
	if (unlikely(!state)) {
		panic("signal_intr_handler is called when g_state is NULL");
		__builtin_unreachable();
	}

	if (state->sig == -1) {
		state->stop = true;
		state->sig  = sig;
		putchar('\n');
	}
}

static void memzero_explicit(void *addr, size_t len)
{
	memset(addr, 0, len);
	__asm__ volatile ("":"+r"(addr)::"memory");
}

static void *alloc_pinned(size_t len)
{
	void *r;
	int err;

	len = (len + 4095ul) & -4096ul;
	r = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
		 -1, 0);
	if (unlikely(r == MAP_FAILED)) {
		err = errno;
		pr_err("mmap(): " PRERF, PREAR(err));
		return NULL;
	}

	err = mlock(r, len);
	if (unlikely(err < 0)) {
		err = errno;
		pr_err("mlock(): " PRERF, PREAR(err));
		munmap(r, len);
		return NULL;
	}
	return r;
}

static void free_pinned(void *p, size_t len)
{
	len = (len + 4095ul) & -4096ul;
	munmap(p, len);
}

static __cold int select_event_loop(struct srv_state *state,
				    struct srv_cfg *cfg)
{
	struct srv_cfg_sock *sock = &cfg->sock;
	const char *evtl = sock->event_loop;

	if ((evtl[0] == '\0') || (!strcmp(evtl, "epoll"))) {
		state->evt_loop_type = EL_EPOLL;
	} else if (!strcmp(evtl, "io_uring") ||
		   !strcmp(evtl, "io uring") ||
		   !strcmp(evtl, "iouring")  ||
		   !strcmp(evtl, "uring")) {
		state->evt_loop_type = EL_IO_URING;
	} else {
		pr_err("Invalid socket event loop: \"%s\"", evtl);
		return -EINVAL;
	}
	return 0;
}

static __cold int init_state(struct srv_state **state_p, struct srv_cfg *cfg)
	__must_hold(&g_state_mutex)
{
	size_t nr_tun_fds = cfg->sys.thread_num;
	struct srv_state *state;
	size_t size;
	size_t i;
	int ret;

	if (cfg->sys.thread_num < 1) {
		pr_error("cfg->sys.thread_num must be at least 1, %hhu given",
			 cfg->sys.thread_num);
		return -EINVAL;
	}

	if (cfg->sock.max_conn < 1) {
		pr_error("cfg->sock.max_conn must be at least 1, %hu given",
			 cfg->sock.max_conn);
		return -EINVAL;
	}

	size = sizeof(*state) + sizeof(int) * nr_tun_fds;
	state = alloc_pinned(size);
	if (!state)
		return -ENOMEM;

	/*
	 * Trigger page-fault early to avoid page-fault later
	 * in the hot-path.
	 */
	memzero_explicit(state, size);

	ret = select_event_loop(state, cfg);
	if (ret)
		goto out_fail;

	for (i = 0; i < nr_tun_fds; i++)
		state->tun_fds[i] = -1;

	state->stop = false;
	state->in_emergency = false;
	state->need_remove_iff = false;
	state->cfg = cfg;
	state->sess = NULL;
	state->udp_fd = -1;
	state->sig = -1;
	state->nr_tun_fds = nr_tun_fds;
	atomic_store(&state->nr_on_threads, 0);

	g_state = state;
	*state_p = state;
	return 0;

out_fail:
	free_pinned(state, size);
	return ret;
}

static __cold int set_signal_handler(bool set)
{
	struct sigaction sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = set ? signal_handler : SIG_DFL;
	if (unlikely(sigaction(SIGINT, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGHUP, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGTERM, &sa, NULL) < 0))
		goto err;

	sa.sa_handler = set ? SIG_IGN : SIG_DFL;
	if (unlikely(sigaction(SIGPIPE, &sa, NULL) < 0))
		goto err;

	return 0;

err:
	ret = errno;
	pr_err("sigaction(): " PRERF, PREAR(ret));
	return -ret;
}

static __cold int socket_setup(int udp_fd, struct srv_state *state)
{
	int y;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;
	int ret;

	y = 6;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}

	y = 1024 * 1024 * 50;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 100;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(ret)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}

	y = 1000;
	ret = setsockopt(udp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(ret)) {
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
	ret = errno;
	pr_err("setsockopt(udp_fd, %s, %s, %d): " PRERF, lv, on, y, PREAR(ret));
	return -ret;
}

static __cold int init_socket(struct srv_state *state)
{
	struct srv_cfg_sock *sock = &state->cfg->sock;
	struct sockaddr_in addr;
	bool non_block;
	int udp_fd;
	int type;
	int ret;

	prl_notice(2, "Initializing UDP socket...");

	non_block = (state->evt_loop_type != EL_IO_URING);
	type = SOCK_DGRAM | (non_block ? SOCK_NONBLOCK : 0);
	udp_fd = socket(AF_INET, type, 0);
	if (udp_fd < 0) {
		const char *q;
		ret = errno;
		q = non_block ? " | SOCK_NONBLOCK" : "";
		pr_error("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF, q,
			 PREAR(ret));
		return -ret;
	}
	prl_notice(2, "UDP socket initialized successfully (fd=%d)", udp_fd);


	prl_notice(2, "Setting up socket configuration...");
	ret = socket_setup(udp_fd, state);
	if (ret)
		goto out_err;


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);
	prl_notice(2, "Binding UDP socket to %s:%hu...", sock->bind_addr,
		   sock->bind_port);


	ret = bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		ret = -errno;
		pr_error("bind(): " PRERF, PREAR(-ret));
		goto out_err;
	}

	state->udp_fd = udp_fd;
	return 0;

out_err:
	__sys_close(udp_fd);
	return ret;
}

static __cold int alloc_tun_fd(const char *dev, short flags, bool non_block)
{
	int ret, tmp;

	ret = tun_alloc(dev, flags);
	if (unlikely(ret < 0)) {
		pr_error("tun_alloc(\"%s\", %d): " PRERF, dev, flags,
			 PREAR(-ret));
		return ret;
	}

	if (!non_block)
		return ret;

	tmp = fd_set_nonblock(ret);
	if (unlikely(tmp < 0)) {
		__sys_close(ret);
		pr_error("fd_set_nonblock(%d): " PRERF, ret, PREAR(-tmp));
		return tmp;
	}

	return ret;
}

static __cold int init_iface(struct srv_state *state)
{
	const short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	const char *dev = state->cfg->iface.dev;
	bool non_block;
	int *tun_fds;
	int ret = 0;
	uint8_t i;

	if (unlikely(!dev || !*dev)) {
		pr_err("iface dev cannot be empty!");
		return -EINVAL;
	}

	prl_notice(2, "Initializing virtual network interface (%s)...", dev);
	tun_fds   = state->tun_fds;
	non_block = (state->evt_loop_type == EL_EPOLL);

	for (i = 0; i < state->nr_tun_fds; i++) {
		prl_notice(4, "Initializing tun_fds[%hhu]...", i);
		ret = alloc_tun_fd(dev, flags, non_block);
		if (unlikely(ret < 0))
			goto err;

		tun_fds[i] = ret;
		prl_notice(4, "Successfully initialized tun_fds[%hhu] (fd=%d)",
			   i, ret);
	}

	if (unlikely(!teavpn_iface_up(&state->cfg->iface.iff))) {
		pr_err("teavpn_iface_up(): cannot bring up network interface");
		ret = -ENETDOWN;
		goto err;
	}

	state->need_remove_iff = true;
	prl_notice(2, "Virtual network interface initialized successfully!");
	return 0;

err:
	while (i--) {
		__sys_close(tun_fds[i]);
		tun_fds[i] = -1;
	}
	return ret;
}

static __cold int init_session_array(struct srv_state *state)
{
	struct udp_sess *sess;
	size_t i, nn, len;

	nn = state->cfg->sock.max_conn;
	len = nn * sizeof(*sess);
	sess = alloc_pinned(len);
	if (!sess)
		return -ENOMEM;

	/*
	 * Trigger page-fault early to avoid page-fault later
	 * in the hot-path.
	 */
	memzero_explicit(sess, len);
	state->sess = sess;
	return 0;
}

static __cold void destroy_state(struct srv_state *state)
	__must_hold(&g_state_mutex)
{
	g_state = NULL;
	free_pinned(state, sizeof(*state));
}

int teavpn2_server_udp_run(struct srv_cfg *cfg)
	__acquires(&g_state_mutex)
	__releases(&g_state_mutex)
{
	struct srv_state *state = NULL;
	int ret;

	mutex_lock(&g_state_mutex);
	ret = init_state(&state, cfg);
	mutex_unlock(&g_state_mutex);
	if (unlikely(ret))
		return ret;

	ret = set_signal_handler(true);
	if (ret)
		goto out;
	ret = init_socket(state);
	if (unlikely(ret))
		goto out_del_sig;
	ret = init_iface(state);
	if (unlikely(ret))
		goto out_del_sig;
	ret = init_session_array(state);
	if (unlikely(ret))
		goto out_del_sig;

out_del_sig:
	set_signal_handler(false);
out:
	mutex_lock(&g_state_mutex);
	destroy_state(state);
	mutex_unlock(&g_state_mutex);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022  Ammar Faizi <ammarfaizi2@gmail.com>
 */
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/ip.h>
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

typedef _Atomic(uint16_t) atomic_u16;

enum {
	EL_EPOLL,
	EL_IO_URING
};

struct udp_sess {
	/*
	 * Private IP address (virtual network interface).
	 */
	uint32_t				ipv4_iff;

	/*
	 * UDP session source address and source port.
	 */
	uint32_t				src_addr;
	uint16_t				src_port;

	/*
	 * UDP sessions are stored in the array, @idx
	 * contains the index of each instance.
	 */
	uint16_t				idx;

	/*
	 * UDP is stateless, we may not know whether the
	 * client is still online or not, @last_act can
	 * be used to handle timeout for session closing
	 * in case we have an abnormal session termination.
	 */
	time_t					last_act;

	/*
	 * Big endian @src_addr and @src_port for sendto() call.
	 */
	struct sockaddr_in			addr;

	/*
	 * Session username.
	 */
	char					username[0x100];

	/*
	 * Human readable C string of @src_addr.
	 */
	char					str_src_addr[IPV4_L];

	/*
	 * Loop counter.
	 */
	uint8_t					loop_c;

	/*
	 * Error counter.
	 */
	uint8_t					err_c;

	bool					is_authenticated;
	bool					is_connected;
};


struct udp_sess_map4;
struct udp_sess_map4 {
	struct udp_sess_map4		*next;
	struct udp_sess			*sess;
};

#define SESS_MAP4_SIZE	(sizeof(struct udp_sess_map4) * 0x100ul * 0x100ul)
#define ROUTE_MAP4_SIZE	(sizeof(atomic_u16) * 0x100ul * 0x100ul)
#define EPOLL_NR_EVENTS	10u

/*
 * Each worker thread represents this struct when using EL_EPOLL.
 */
struct epoll_wrk {
	struct srv_state			*state;
	pthread_t				thread;

	/*
	 * epoll file descriptor.
	 */
	int					fd;

	/*
	 * epoll timeout.
	 */
	int					timeout;

	/*
	 * Events returned by the epoll_wait().
	 */
	struct epoll_event			events[EPOLL_NR_EVENTS];

	/*
	 * Is this thread online?
	 */
	_Atomic(bool)				is_on;

	/*
	 * Workers are stored in the array, @idx represents
	 * the index.
	 */
	uint16_t				idx;

	/*
	 * Buffer to handle read() from tun_fd.
	 */
	struct sc_pkt				pkt;
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
	 * Number of online sessions.
	 */
	_Atomic(uint16_t)		nr_on_sess;

	/*
	 * A pointer to the struct srv_cfg that contains
	 * TeaVPN2 server configuration.
	 */
	struct srv_cfg			*cfg;

	/*
	 * Array of UDP sessions.
	 */
	struct udp_sess			*sess;

	union {
		struct epoll_wrk		*epoll_threads;
	};

	/*
	 * Session mapping for IPv4 clients.
	 */
	struct udp_sess_map4		(*sess_map4)[0x100];
	struct tmutex			sess_map4_lock;

	/*
	 * A small hash table for route lookup.
	 */
	atomic_u16			(*route_map4)[0x100];

	/*
	 * Stack to get unused UDP session index in O(1).
	 */
	struct bt_stack			sess_stk;
	struct tmutex			sess_stk_lock;

	/*
	 * The number of elements in the @tun_fds array.
	 *
	 * The number of elements in @tun_fds is currently
	 * the same with @cfg->sys.thread_num.
	 */
	uint16_t			nr_tun_fds;

	/*
	 * Received signal from the signal handler.
	 */
	int				sig;

	/*
	 * The file descriptor of the server UDP socket.
	 */
	int				udp_fd;

	/*
	 * The array of file descriptors of the TUN interface.
	 */
	int				tun_fds[];
};

#define W_IP(CLIENT) 	((CLIENT)->str_src_addr), ((CLIENT)->src_port)
#define W_UN(CLIENT) 	((CLIENT)->username)
#define W_IU(CLIENT) 	W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 		"%s:%d (%s) (cli_idx=%hu)"

static DEFINE_MUTEX(g_state_mutex);
static struct srv_state *g_state = NULL;

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

static __always_inline size_t srv_pprep_sync(struct srv_pkt *srv_pkt)
{
	return srv_pprep(srv_pkt, TSRV_PKT_SYNC, 0, 0);
}

static __always_inline size_t srv_pprep_reqsync(struct srv_pkt *srv_pkt)
{
	return srv_pprep(srv_pkt, TSRV_PKT_REQSYNC, 0, 0);
}

__maybe_unused static inline int PTR_ERR(const void *ptr)
{
	return (int) (intptr_t) ptr;
}

__maybe_unused static inline void *ERR_PTR(int err)
{
	return (void *) (intptr_t) err;
}

__maybe_unused static inline bool IS_ERR(const void *ptr)
{
	return unlikely((uintptr_t) ptr >= (uintptr_t) -4095UL);
}

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

static void *alloc_pinned_faulted(size_t len)
{
	void *ret;

	ret = alloc_pinned(len);
	if (unlikely(!ret))
		return ret;

	memzero_explicit(ret, len);
	return ret;
}

static void free_pinned(void *p, size_t len)
{
	if (unlikely(!p))
		return;

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
	state = alloc_pinned_faulted(size);
	if (!state)
		return -ENOMEM;

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

	y = 1024 * 1024 * 100;
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

	/*
	 * Do not use a non-blocking socket if the event
	 * loop is io_uring.
	 */
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
	static const short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
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
	tun_fds = state->tun_fds;
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

static void reset_session(struct udp_sess *sess, uint16_t idx)
{
	memset(sess, 0, sizeof(*sess));
	sess->idx = idx;
}

static __cold int init_session_array(struct srv_state *state)
{
	struct udp_sess *sess;
	size_t i, nn, len;

	nn = state->cfg->sock.max_conn;
	len = nn * sizeof(*sess);
	sess = alloc_pinned_faulted(len);
	if (!sess)
		return -ENOMEM;

	for (i = 0; i < nn; i++)
		reset_session(&sess[i], (uint16_t)i);

	state->sess = sess;
	return 0;
}

static __cold int init_session_stack(struct srv_state *state)
{
	uint16_t i, max_conn = state->cfg->sock.max_conn;
	int ret;

	prl_notice(4, "Initializing UDP session stack...");
	if (unlikely(!bt_stack_init(&state->sess_stk, max_conn)))
		return -errno;

#ifndef NDEBUG
	for (i = 0; i < 100; i++)
		bt_stack_test(&state->sess_stk);
#endif

	for (i = max_conn; i--;) {
		int32_t tmp = bt_stack_push(&state->sess_stk, (uint16_t)i);
		if (unlikely(tmp == -1)) {
			panic("Fatal bug in init_udp_session_stack!");
			__builtin_unreachable();
		}
	}

	ret = mutex_init(&state->sess_stk_lock, NULL);
	if (ret) {
		bt_stack_destroy(&state->sess_stk);
		memset(&state->sess_stk, 0, sizeof(state->sess_stk));
		return -ret;
	}

	return 0;
}

static __cold int init_session_map_ipv4(struct srv_state *state)
{
	struct udp_sess_map4 (*sess_map4)[0x100] = NULL;
	int err;

	sess_map4 = alloc_pinned_faulted(SESS_MAP4_SIZE);
	if (!sess_map4)
		return -ENOMEM;

	err = mutex_init(&state->sess_map4_lock, NULL);
	if (err) {
		free_pinned(sess_map4, SESS_MAP4_SIZE);
		return -err;
	}

	state->sess_map4 = sess_map4;
	return 0;
}


static __cold int init_route_map_ipv4(struct srv_state *state)
{
	atomic_u16 (*route_map4)[0x100] = NULL;
	int err;

	route_map4 = alloc_pinned_faulted(ROUTE_MAP4_SIZE);
	if (!route_map4)
		return -ENOMEM;

	state->route_map4 = route_map4;
	return 0;
}

static __cold int el_epl_init_threads_data(struct srv_state *state)
{
	size_t nn = (size_t)state->cfg->sys.thread_num;
	struct epoll_wrk *threads;
	struct epoll_wrk *thread;
	size_t i;

	if (WARN_ON(nn < 1)) {
		nn = 1;
		state->cfg->sys.thread_num = 1;
	}

	threads = alloc_pinned_faulted(nn * sizeof(threads));
	if (!threads)
		return -ENOMEM;

	state->epoll_threads = threads;

	/*
	 * Initialize all @fd to -1, in case we fail to
	 * create the epoll instance, the close function
	 * will know which fds need to be closed.
	 *
	 * If the fd is -1, it does not need to be closed.
	 */
	for (i = 0; i < nn; i++) {
		thread = &threads[i];
		thread->idx = i;
		thread->state = state;
		thread->fd = -1;
	}

	return 0;
}

static int epoll_add(struct epoll_wrk *thread, int fd, uint32_t events,
		     epoll_data_t data)
{
	int epoll_fd = thread->fd;
	struct epoll_event evt;
	int ret;

	memset(&evt, 0, sizeof(evt));
	evt.events = events;
	evt.data = data;
	prl_notice(4, "[for thread %u] Adding fd (%d) to epoll_fd (%d)",
		   thread->idx, fd, epoll_fd);

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &evt);
	if (unlikely(ret < 0)) {
		ret = -errno;
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d, events): " PRERF,
			epoll_fd, fd, PREAR(-ret));
	}
	return ret;
}

static __cold int el_epl_register_tun_fds(struct srv_state *state,
					  struct epoll_wrk *thread)
{
	const uint32_t events = EPOLLIN | EPOLLPRI;
	uint8_t nn = state->cfg->sys.thread_num;
	int *tun_fds = state->tun_fds;
	epoll_data_t data;
	int ret;

	memset(&data, 0, sizeof(data));
	if (thread->idx == 0) {
		/*
		 * Main thread is responsible to handle data
		 * from the UDP socket.
		 */
		data.fd = state->udp_fd;
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (nn == 1) {
			/*
			 * If we are single-threaded, the main thread
			 * is also responsible to read from TUN fd.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	} else {
		data.fd = tun_fds[thread->idx];
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (thread->idx == 1) {
			/*
			 * If we are multithreaded, the subthread is responsible
			 * to read from tun_fds[0]. Don't give this work to the
			 * main thread for better concurrency.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	}

	return 0;
}

static __cold int el_epl_init_epoll(struct srv_state *state)
{
	size_t i, nn = (size_t)state->cfg->sys.thread_num;
	struct epoll_wrk *threads = state->epoll_threads;

	prl_notice(2, "Initializing epoll fd...");
	for (i = 0; i < nn; i++) {
		int ret;

		ret = epoll_create(255);
		if (ret < 0) {
			/*
			 * If we fail at (i > 0) the caller is responsible
			 * to close the active epoll fds.
			 */
			ret = -errno;
			pr_err("epoll_create(): " PRERF, PREAR(-ret));
			return ret;
		}

		threads[i].fd = ret;
		threads[i].timeout = 1000;
		ret = el_epl_register_tun_fds(state, &threads[i]);
		if (unlikely(ret))
			return ret;

		prl_notice(5, "epoll_threads[%zu].fd = %d", i, ret);
	}
	return 0;
}

static noinline __cold void el_epl_wait_threads(struct epoll_wrk *thread)
{
	static _Atomic(bool) release_sub_thread = false;
	struct srv_state *state = thread->state;
	uint8_t nn = state->cfg->sys.thread_num;

	if (thread->idx != 0) {
		/*
		 * We are a sub thread.
		 * Waiting for the main thread be ready...
		 */
		while (!atomic_load(&release_sub_thread)) {
			if (unlikely(state->stop))
				return;
			usleep(100000);
		}
		return;
	}

	/*
	 * We are the main thread. Wait for all threads
	 * to be spawned properly.
	 */
	while (atomic_load(&state->nr_on_threads) != nn) {
		prl_notice(2, "Waiting for subthread(s) be ready...");
		if (unlikely(state->stop))
			return;
		usleep(100000);
	}

	if (nn > 1)
		prl_notice(2, "All threads are ready!");
	prl_notice(2, "Initialization Sequence Completed");
	atomic_store(&release_sub_thread, true);
	return;
}

static struct udp_sess_map4 *get_sess_map4(
	struct udp_sess_map4 (*sess_map4)[0x100], uint32_t addr)
{
	size_t idx1, idx2;
	idx1 = (addr >> 0u) & 0xffu;
	idx2 = (addr >> 8u) & 0xffu;
	return &sess_map4[idx1][idx2];
}

static __hot struct udp_sess *lookup_udp_sess_map4(struct srv_state *state,
						   uint32_t addr, uint16_t port)
	__acquires(&state->sess_map4_lock)
	__releases(&state->sess_map4_lock)
{
	struct udp_sess_map4 *iter;
	struct udp_sess *ret;

	mutex_lock(&state->sess_map4_lock);
	iter = get_sess_map4(state->sess_map4, addr);
	do {
		ret = iter->sess;
		if (!ret)
			break;

		if (ret->src_addr == addr && ret->src_port == port)
			/*
			 * OK, we found it, this is an active session!
			 */
			break;

		ret = NULL;
		iter = iter->next;
	} while (iter);
	mutex_unlock(&state->sess_map4_lock);
	return ret;
}

static int insert_udp_sess_map4(struct srv_state *state, uint32_t addr,
				struct udp_sess *sess)
	__acquires(&state->sess_map4_lock)
	__releases(&state->sess_map4_lock)
{
	struct udp_sess_map4 *iter, *next;
	int ret = 0;

	mutex_lock(&state->sess_map4_lock);
	iter = get_sess_map4(state->sess_map4, addr);
	if (!iter->sess) {
		iter->sess = sess;
		/*
		 * If first entry is empty, there should
		 * be no next!
		 */
		if (WARN_ON(iter->next != NULL))
			iter->next = NULL;
		goto out;
	}

	next = malloc(sizeof(*next));
	if (unlikely(!next)) {
		pr_err("Cannot allocate memory on insert_udp_sess_map4()!");
		ret = -ENOMEM;
		goto out;
	}

	next->next = NULL;
	next->sess = sess;

	while (iter->next)
		iter = iter->next;
	iter->next = next;
out:
	mutex_unlock(&state->sess_map4_lock);
	return ret;
}

static struct udp_sess *create_udp_sess4(struct srv_state *state, uint32_t addr,
					 uint16_t port,
					 struct sockaddr_in *saddr)
	__acquires(&state->sess_stk_lock)
	__releases(&state->sess_stk_lock)
{
	struct udp_sess *ret;
	int32_t stk_ret;
	uint16_t idx;
	int err;

	mutex_lock(&state->sess_stk_lock);
	stk_ret = bt_stack_pop(&state->sess_stk);
	mutex_unlock(&state->sess_stk_lock);
	if (unlikely(stk_ret == -1)) {
		pr_err("Client session is full, cannot accept more client!");
		return ERR_PTR(-EAGAIN);
	}

	idx = (uint16_t) stk_ret;
	ret = &state->sess[idx];
	err = insert_udp_sess_map4(state, addr, ret);
	if (unlikely(err)) {
		mutex_lock(&state->sess_stk_lock);
		BUG_ON(bt_stack_push(&state->sess_stk, idx) == -1);
		mutex_unlock(&state->sess_stk_lock);
		return ERR_PTR(err);
	}

	ret->src_addr = addr;
	ret->src_port = port;
	ret->addr = *saddr;
	ret->is_connected = true;
	addr = htonl(addr);
	WARN_ON(!inet_ntop(AF_INET, &addr, ret->str_src_addr,
			   sizeof(ret->str_src_addr)));
	atomic_fetch_add_explicit(&state->nr_on_sess, 1, memory_order_relaxed);

	return ret;
}

struct handshake_ctx {
	char		rej_msg[512];
	uint8_t		rej_reason;
};

static int check_client_handshake(struct cli_pkt *cli_pkt, size_t len,
				  struct handshake_ctx *ctx,
				  struct udp_sess *sess)
{
	struct pkt_handshake *hand = &cli_pkt->handshake;
	size_t expected_len = sizeof(*hand);
	uint8_t *rrs = &ctx->rej_reason;
	size_t mlen = sizeof(ctx->rej_msg);
	struct teavpn2_version *cur;
	char *mbuf = ctx->rej_msg;

	if (len < (PKT_MIN_LEN + expected_len)) {
		snprintf(mbuf, mlen, "Invalid handshake packet length from "
			 PRWIU " (expected at least %zu bytes; actual = %zu "
			 "bytes)", W_IU(sess), (PKT_MIN_LEN + expected_len),
			 len);
		*rrs = TSRV_HREJECT_INVALID;
		return -EBADMSG;
	}

	cli_pkt->len = ntohs(cli_pkt->len);
	if ((size_t)cli_pkt->len != expected_len) {
		snprintf(mbuf, mlen, "Invalid handshake packet length from "
			 PRWIU " (expected = %zu; actual: cli_pkt->len = %hu)",
			 W_IU(sess), expected_len, cli_pkt->len);
		*rrs = TSRV_HREJECT_INVALID;
		return -EBADMSG;
	}

	if (cli_pkt->type != TCLI_PKT_HANDSHAKE) {
		snprintf(mbuf, mlen,  "Invalid first packet type from " PRWIU
			 " (expected = TCLI_PKT_HANDSHAKE (%u); actual = %hhu)",
			 W_IU(sess), TCLI_PKT_HANDSHAKE, cli_pkt->type);
		*rrs = TSRV_HREJECT_INVALID;
		return -EBADMSG;
	}

	cur = &hand->cur;
	/*
	 * Always put a NUL char at the end of
	 * the array for printing safety!
	 *
	 * Reasoning:
	 * The buffer is not trusted, it comes
	 * from the client, it can be arbitrary.
	 */
	cur->extra[sizeof(cur->extra) - 1] = '\0';
	prl_notice(2, "New connection from " PRWIU
		   " (client version: TeaVPN2-%hhu.%hhu.%hhu%s)",
		   W_IU(sess),
		   cur->ver,
		   cur->patch_lvl,
		   cur->sub_lvl,
		   cur->extra);

	if ((cur->ver != VERSION) || (cur->patch_lvl != PATCHLEVEL) ||
	    (cur->sub_lvl != SUBLEVEL)) {
		prl_notice(2, "Dropping connection from " PRWIU
			   " (version not supported)...", W_IU(sess));
		*rrs = TSRV_HREJECT_VERSION_NOT_SUPPORTED;
		return -EBADMSG;
	}

	return 0;
}

static __hot ssize_t el_epl_send_to_client(struct epoll_wrk *thread,
					   struct udp_sess *sess,
					   const void *buffer, size_t buflen,
					   int flags)
{
	ssize_t ret;

	ret = __sys_sendto(thread->state->udp_fd, buffer, buflen, flags,
			   (struct sockaddr *)&sess->addr, sizeof(sess->addr));
	if (unlikely(ret < 0))
		pr_err("sendto(): " PRERF, PREAR(-ret));

	return ret;
}

static int el_epl_send_handshake(struct epoll_wrk *thread,
				 struct udp_sess *sess)
{
	struct srv_pkt *srv_pkt = &thread->pkt.srv;
	ssize_t ret;
	size_t len;

	len = srv_pprep_handshake(srv_pkt);
	ret = el_epl_send_to_client(thread, sess, srv_pkt, len, MSG_DONTWAIT);
	if (unlikely((size_t)ret != len)) {
		pr_error("%s(): send_ret (%zd) != send_len (%zu), client: "
			 PRWIU, __func__, ret, len, W_IU(sess));
		return -EAGAIN;
	}

	if (likely(ret > 0))
		return 0;

	return (int)ret;
}

static int _el_epl_handle_new_conn(struct epoll_wrk *thread,
				   struct udp_sess *sess)
{
	struct sc_pkt *pkt = &thread->pkt;
	struct handshake_ctx hctx;
	int ret;

	ret = check_client_handshake(&pkt->cli, pkt->len, &hctx, sess);
	if (ret) {
		/*
		 * TODO: Handshake failed, drop the client session!
		 */

		if (ret == -EBADMSG) {
			prl_notice(2, "%s", hctx.rej_msg);

			/*
			 * If the handle_client_handshake() returns
			 * -EBADMSG, this means the client has sent
			 * a bad handshake packet. It's not our
			 * fault, so return 0 as, we, as the server,
			 * are still fine.
			 */
			return 0;
		}
	}

	/*
	 * We received a good packet, send a handshake
	 * packet reply to the client.
	 *
	 * Let's welcome them :-)
	 */
	ret = el_epl_send_handshake(thread, sess);
	if (unlikely(ret)) {
		/*
		 * For some reason we fail to send a handshake.
		 * Let's just drop this client.
		 */

		/*
		 * TODO: Handshake failed, drop the client session!
		 */

		/*
		 * If we get a -EAGAIN, it's just a non-blocking
		 * socket behavior, we are fine in that case.
		 * But still, we drop the client, because the
		 * handshake fails.
		 */
		return (ret == -EAGAIN) ? 0 : ret;
	}

	return ret;
}

static int el_epl_handle_new_conn(struct epoll_wrk *thread, uint32_t addr,
				  uint16_t port, struct sockaddr_in *saddr)
{
	struct udp_sess *sess;
	int ret = 0;

	/*
	 * Only create a new session when a new client
	 * sends a handshake pakcet. Otherwise, ignore
	 * it.
	 */
	if (thread->pkt.cli.type != TCLI_PKT_HANDSHAKE)
		return 0;

	sess = create_udp_sess4(thread->state, addr, port, saddr);
	if (IS_ERR(sess)) {
		ret = PTR_ERR(sess);

		/*
		 * Don't fail if the failure reason is:
		 *   "the session array is full".
		 */
		return (ret == -EAGAIN) ? 0 : ret;
	}

	/*
	 * If we succeed in calling create_udp_sess4(),
	 * we must have it on the map. If we don't have,
	 * then, it's a bug!
	 */
	BUG_ON(lookup_udp_sess_map4(thread->state, addr, port) != sess);
	return _el_epl_handle_new_conn(thread, sess);
}

static void del_ipv4_route_map(atomic_u16 (*map)[0x100], uint32_t addr)
{
	uint16_t byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	atomic_store(&map[byte0][byte1], 0);
}

static void set_ipv4_route_map(atomic_u16 (*map)[0x100], uint32_t addr,
			       uint16_t maps_to)
{
	uint16_t byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	atomic_store(&map[byte0][byte1], maps_to + 1);
}

static int32_t get_ipv4_route_map(atomic_u16 (*map)[0x100], uint32_t addr)
{
	uint16_t ret, byte0, byte1;

	byte0 = (addr >> 0u) & 0xffu;
	byte1 = (addr >> 8u) & 0xffu;
	ret = atomic_load(&map[byte0][byte1]);

	if (ret == 0)
		/* Unmapped address. */
		return -ENOENT;

	return (int32_t)(ret - 1);
}

static __hot int el_epl_handle_auth_pkt(struct epoll_wrk *thread,
					struct udp_sess *sess)
{
	size_t expected_len = PKT_MIN_LEN + sizeof(struct pkt_auth);
	struct sc_pkt *pkt = &thread->pkt;
	struct cli_pkt *cli_pkt = &pkt->cli;
	struct srv_pkt *srv_pkt = &pkt->srv;
	struct pkt_auth_res *auth_res = &srv_pkt->auth_res;
	struct pkt_auth auth;
	uint32_t ipv4_iff;
	ssize_t send_ret;
	size_t send_len;
	bool tmp;

	if (unlikely(pkt->len < expected_len)) {
		pr_error("Invalid handshake packet from " PRWIU ": recvfrom() "
			 "returned %zu but the expected_len is at least %zu.",
			 W_IU(sess), pkt->len, expected_len);
		return -EBADMSG;
	}

	if (unlikely(sess->is_authenticated))
		/*
		 * This client has already been authenticated.
		 * Why does it send an authentication packet again?
		 *
		 * Ignore it...
		 */
		return 0;

	/*
	 * NOTE!
	 *
	 * @thread->pkt is a union. @cli_pkt and @srv_pkt live in the
	 * the same memory region. On teavpn2_auth() call, we will
	 * clobber the content of @srv_pkt, so we need to copy the
	 * auth packet here. Ohterwise, the client's auth packet
	 * will be clobbered by that call.
	 */
	auth = cli_pkt->auth;
	/*
	 * Alywas put a NUL char at the end.
	 *
	 * Reasoning:
	 * Keep it safe for string function operations. This buffer
	 * comes from the client, it can be arbitrary.
	 */
	auth.username[sizeof(auth.username) - 1] = '\0';
	auth.password[sizeof(auth.password) - 1] = '\0';
	prl_notice(2, "Got auth packet from (user: %s) " PRWIU, auth.username,
		   W_IU(sess));

	/*
	 * Make sure we clear the sensitive string from
	 * memory as soon as it's no longer used.
	 */
	memzero_explicit(cli_pkt->auth.password, sizeof(cli_pkt->auth.password));
	tmp = teavpn2_auth(auth.username, auth.password, &auth_res->iff);
	memzero_explicit(auth.password, sizeof(auth.password));

	if (!tmp) {
		/*
		 * Authentication fails.
		 *
		 * TODO: Drop the client. Still return 0 after drop.
		 */
		return 0;
	}

	/*
	 * Authentication succeed!
	 *
	 * Now send the virtual network interface config to the
	 * client. The config already lives in @auth_res->iff.
	 *
	 * We will send the whole @srv_pkt, so a raw prep here.
	 */
	send_len = srv_pprep(srv_pkt, TSRV_PKT_AUTH_OK, sizeof(*auth_res), 0);
	send_ret = el_epl_send_to_client(thread, sess, srv_pkt, send_len,
					 MSG_DONTWAIT);
	if (unlikely(send_ret < 0)) {
		/*
		 * TODO: Drop the client.
		 */

		if (send_ret == -EAGAIN)
			return 0;

		return send_ret;
	}

	ipv4_iff = ntohl(inet_addr(auth_res->iff.ipv4));
	sess->ipv4_iff = ipv4_iff;
	sess->is_authenticated = true;
	set_ipv4_route_map(thread->state->route_map4, ipv4_iff, sess->idx);
	return 0;
}

static __cold int el_epl_handle_pkt_write_error(struct udp_sess *sess,
						int tun_fd, size_t len,
						ssize_t ret)
{
	if (ret == 0) {
		pr_err("Network is down, write(tun_fd=%d) returns 0 when "
		       "receiving tun data from " PRWIU, tun_fd, W_IU(sess));
		return -ENETDOWN;
	}

	if (ret > 0) {
		pr_err("Got short write(tun_fd=%d) (ret = %zd; expected = %zu) "
		       "when receiving tun data from " PRWIU, tun_fd, ret, len,
		       W_IU(sess));
		return 0;
	}

	pr_err("write(tun_fd=%d) error when receiving data from " PRWIU ": "
	       PRERF, tun_fd, W_IU(sess), PREAR(-ret));

	return (int)ret;
}

static __hot int el_epl_handle_tun_pkt(struct epoll_wrk *thread,
				       struct udp_sess *sess)
{
	struct sc_pkt *pkt = &thread->pkt;
	struct cli_pkt *cli_pkt = &pkt->cli;
	int tun_fd = thread->state->tun_fds[0];
	size_t data_len, expt_len, recv_ret;
	ssize_t ret;

	data_len = ntohs(cli_pkt->len);
	if (unlikely(data_len == 0))
		return 0;

	/*
	 *
	 * The returned size by recvfrom() must be equal to:
	 *
	 *   PKT_MIN_LEN + ntohs(@cli_pkt->len) + @cli_pkt->pad_len
	 *
	 * Otherwise, something goes wrong!
	 *
	 */
	expt_len = PKT_MIN_LEN + data_len + cli_pkt->pad_len;
	recv_ret = pkt->len;
	if (unlikely(recv_ret != expt_len)) {
		pr_error("%s(): recv_ret (%zu) != expt_len (%zu) from " PRWIU,
			 __func__, recv_ret, expt_len, W_IU(sess));
		return -EBADMSG;
	}

	ret = __sys_write(tun_fd, cli_pkt->__raw, data_len);
	if (unlikely((size_t)ret != data_len))
		return el_epl_handle_pkt_write_error(sess, tun_fd, data_len,
						     ret);

	return 0;
}

static __hot int _el_epl_handle_event_udp(struct epoll_wrk *thread,
					  struct sockaddr_in *saddr)
{
	struct srv_state *state = thread->state;
	struct udp_sess *sess;
	uint32_t addr;
	uint16_t port;
	int ret = 0;

	port = ntohs(saddr->sin_port);
	addr = ntohl(saddr->sin_addr.s_addr);
	sess = lookup_udp_sess_map4(state, addr, port);
	if (unlikely(!sess))
		/*
		 * We don't find the corresponding @addr and @port
		 * in the session map, it means we get a new client.
		 *
		 * We will be performing a handshake with them here...
		 */
		return el_epl_handle_new_conn(thread, addr, port, saddr);


	switch (thread->pkt.cli.type) {
	case TCLI_PKT_AUTH:
		ret = el_epl_handle_auth_pkt(thread, sess);
		break;
	case TCLI_PKT_TUN_DATA:
		ret = el_epl_handle_tun_pkt(thread, sess);
		break;
	case TCLI_PKT_REQSYNC:
	case TCLI_PKT_SYNC:
	case TCLI_PKT_CLOSE:
		return 0;
	}

	if (unlikely(ret == -EBADMSG)) {
		/*
		 * Got a bad packet from the client.
		 *
		 * TODO: Request sync here...
		 */
		pr_notice("Bad packet!");
		return 0;
	}

	return ret;
}

static __hot int el_epl_handle_event_udp(struct epoll_wrk *thread, int fd)
{
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);
	ssize_t ret;

	ret = __sys_recvfrom(fd, &thread->pkt.srv, sizeof(thread->pkt.srv), 0,
			     (struct sockaddr *)&saddr, &saddr_len);
	if (unlikely(ret <= 0)) {

		if (ret == -EAGAIN)
			/*
			 * Handle non-blocking socket behavior.
			 * Do not treat this as an error.
			 */
			return 0;

		if (ret == 0) {
			pr_err("recvfrom() returned 0, network down?");
			return -ENETDOWN;
		}

		pr_err("recvfrom(): " PRERF, PREAR(-ret));
		return ret;
	}

	prl_notice(4, "recvfrom(): %zd bytes", ret);
	thread->pkt.len = (size_t)ret;
	return _el_epl_handle_event_udp(thread, &saddr);
}

static __hot int el_epl_route_ipv4_packet(struct epoll_wrk *thread,
					  uint32_t dst_addr,
					  struct pkt_tun_data *tdata,
					  size_t len)
{
	struct udp_sess *sess;
	uint16_t idx;
	int32_t find;
	ssize_t ret;

	find = get_ipv4_route_map(thread->state->route_map4, dst_addr);
	if (unlikely(find < 0))
		return (int)find;

	idx = (uint16_t)find;
	sess = &thread->state->sess[idx];
	ret = el_epl_send_to_client(thread, sess, tdata, len, MSG_DONTWAIT);
	if (unlikely(ret < 0))
		return (int)ret;

	return 0;
}

static __hot int el_epl_route_packet(struct epoll_wrk *thread,
				     struct pkt_tun_data *tdata,
				     size_t len)
{
	struct iphdr *iphdr = &tdata->iphdr;
	int ret = 0;

	if (likely(iphdr->version == 4)) {
		uint32_t dst_addr = ntohl(iphdr->daddr);

		ret = el_epl_route_ipv4_packet(thread, dst_addr, tdata, len);
		if (likely(ret != -ENOENT))
			return 0;
	} else {
		/* TODO: Handle IPv6 packets. */
	}

	return ret;
}

static __hot int el_epl_handle_event_tun(struct epoll_wrk *thread, int fd)
{
	struct pkt_tun_data *tdata = &thread->pkt.srv.tun_data;
	ssize_t ret;

	ret = __sys_read(fd, tdata, sizeof(*tdata));
	if (unlikely(ret < 0)) {

		if (ret == -EAGAIN)
			/*
			 * Handle non-blocking socket behavior.
			 * Do not treat this as an error.
			 */
			return 0;

		if (ret == 0) {
			pr_error("read() returned 0, network down?");
			return -ENETDOWN;
		}

		pr_err("read(tun_fd) (fd=%d): " PRERF, fd, PREAR(-ret));
		return ret;
	}

	return el_epl_route_packet(thread, tdata, (size_t)ret);
}

static __hot int el_epl_handle_event(struct epoll_wrk *thread,
				     struct epoll_event *event)
{
	struct srv_state *state = thread->state;
	int fd = event->data.fd;
	int ret = 0;

	if (fd == state->udp_fd)
		ret = el_epl_handle_event_udp(thread, fd);
	else
		ret = el_epl_handle_event_tun(thread, fd);

	return ret;
}

static __hot int do_epoll_wait(struct epoll_wrk *thread)
{
	struct epoll_event *events = thread->events;
	int timeout = thread->timeout;
	int fd = thread->fd;
	int ret;

	ret = __sys_epoll_wait(fd, events, EPOLL_NR_EVENTS, timeout);
	if (unlikely(ret < 0)) {
		if (ret == -EINTR) {
			prl_notice(2, "[thread=%hu] Interrupted!", thread->idx);
			return 0;
		}
		pr_error("[thread=%u] epoll_wait(): " PRERF, thread->idx,
			 PREAR(-ret));
	}
	return ret;
}

static __hot int el_epl_run_event_loop(struct epoll_wrk *thread)
{
	struct epoll_event *events;
	int ret;
	int tmp;
	int i;

	ret = do_epoll_wait(thread);
	if (unlikely(ret < 0))
		return ret;

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = el_epl_handle_event(thread, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}

static noinline void *el_epl_wrk(void *thread_p)
{
	struct epoll_wrk *thread = thread_p;
	struct srv_state *state = thread->state;
	int ret = 0;

	atomic_fetch_add(&state->nr_on_threads, 1);
	atomic_store(&thread->is_on, true);
	el_epl_wait_threads(thread);

	while (!state->stop) {
		ret = el_epl_run_event_loop(thread);
		if (unlikely(ret))
			break;
	}

	prl_notice(2, "epoll_threads[%zu] is exiting...", (size_t)thread->idx);
	atomic_store(&thread->is_on, false);
	atomic_fetch_sub(&state->nr_on_threads, 1);
	return (void *)((intptr_t)ret);
}

static __cold int el_epl_spawn_thread(struct epoll_wrk *thread)
{
	char tname[sizeof("epoll-wrk-xxxxx")];
	int ret;

	ret = pthread_create(&thread->thread, NULL, el_epl_wrk, thread);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(thread->thread);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	snprintf(tname, sizeof(tname), "epoll-wrk-%hu", thread->idx);
	ret = pthread_setname_np(thread->thread, tname);
	if (unlikely(ret)) {
		pr_err("pthread_setname_np(): " PRERF, PREAR(ret));
		ret = 0;
	}
	return ret;
}

static __cold int el_epl_spawn_threads(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	size_t i, nn = (size_t)state->cfg->sys.thread_num;

	/*
	 * @threads[0] is executed by the main thread,
	 * don't spawn an LWP for it.
	 */
	for (i = 1; i < nn; i++) {
		int ret;

		prl_notice(2, "Spawning threads[%zu]...", i);
		ret = el_epl_spawn_thread(&threads[i]);
		if (unlikely(ret))
			return ret;
	}
	return 0;
}

static noinline __cold void el_epl_join_threads(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	_Atomic(uint16_t) *nrp = &state->nr_on_threads;
	struct epoll_wrk *thread;
	uint16_t i, r;
	int err;

	r = atomic_load(nrp);
	if (!r)
		return;

	r = state->cfg->sys.thread_num;
	for (i = 0; i < r; i++) {
		thread = &threads[i];
		if (!atomic_load(&thread->is_on))
			continue;
		err = pthread_kill(thread->thread, SIGTERM);
		if (err)
			pr_error("pthread_kill(): " PRERF, PREAR(err));
	}


	do {
		r = atomic_load(nrp);
		if (r) {
			pr_notice("Waiting for %hu thread(s) to exit...", r);
			usleep(500000);
		}
	} while (r);
}

static __cold void destroy_epoll_threads(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	size_t i, nn;

	if (!threads)
		return;

	el_epl_join_threads(state);

	nn = (size_t)state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		struct epoll_wrk *thread = &threads[i];
		int fd;

		fd = thread->fd;
		if (fd == -1)
			continue;
		prl_notice(2, "Closing epoll_threads[%zu] (fd=%d)...", i, fd);
		__sys_close(fd);
	}
	free_pinned(threads, nn * sizeof(threads));
}

static int el_epl_run_server(struct srv_state *state)
{
	int ret = 0;
	void *ret_p;

	ret = el_epl_init_threads_data(state);
	if (unlikely(ret))
		return ret;
	ret = el_epl_init_epoll(state);
	if (unlikely(ret))
		goto out;
	ret = el_epl_spawn_threads(state);
	if (unlikely(ret))
		goto out;
	ret_p = el_epl_wrk(&state->epoll_threads[0]);
	ret = (int)((intptr_t)ret_p);
out:
	destroy_epoll_threads(state);
	return ret;
}

static int run_server_event_loop(struct srv_state *state)
{
	switch (state->evt_loop_type) {
	case EL_EPOLL:
		return el_epl_run_server(state);
	case EL_IO_URING:
		pr_error("run_client_event_loop() with io_uring: " PRERF,
			 PREAR(EOPNOTSUPP));
		return -EOPNOTSUPP;
	}

	pr_err("Invalid event loop type: %hhu", state->evt_loop_type);
	return -EINVAL;
}

static __cold void destroy_sess(struct srv_state *state)
{
	size_t len;

	if (!state->sess)
		return;
	len = state->cfg->sock.max_conn * sizeof(*state->sess);
	free_pinned(state->sess, len);
}

static __cold void destroy_sess_map4(struct srv_state *state)
{
	if (!state->sess_map4)
		return;
	mutex_lock(&state->sess_map4_lock);
	free_pinned(state->sess_map4, SESS_MAP4_SIZE);
	mutex_unlock(&state->sess_map4_lock);
	mutex_destroy(&state->sess_map4_lock);
}

static __cold void destroy_route_map4(struct srv_state *state)
{
	if (!state->route_map4)
		return;
	free_pinned(state->route_map4, ROUTE_MAP4_SIZE);
}

static __cold void destroy_sess_stack(struct srv_state *state)
{
	if (!state->sess_stk.arr)
		return;
	mutex_lock(&state->sess_stk_lock);
	bt_stack_destroy(&state->sess_stk);
	mutex_unlock(&state->sess_stk_lock);
	mutex_destroy(&state->sess_stk_lock);
}

static __cold void destroy_tun_fds(struct srv_state *state)
{
	int *tun_fds = state->tun_fds;
	uint8_t i, nn;

	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		if (tun_fd == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fd);
		__sys_close(tun_fd);
	}
}

static __cold void destroy_state(struct srv_state *state)
	__must_hold(&g_state_mutex)
{
	g_state = NULL;
	destroy_sess(state);
	destroy_sess_map4(state);
	destroy_route_map4(state);
	destroy_sess_stack(state);
	destroy_tun_fds(state);
	free_pinned(state, sizeof(*state) + sizeof(int) * state->nr_tun_fds);
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
	if (unlikely(ret))
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
	ret = init_session_stack(state);
	if (unlikely(ret))
		goto out_del_sig;
	ret = init_session_map_ipv4(state);
	if (unlikely(ret))
		goto out_del_sig;
	ret = init_route_map_ipv4(state);
	if (unlikely(ret))
		goto out_del_sig;
	ret = run_server_event_loop(state);

out_del_sig:
	set_signal_handler(false);
out:
	mutex_lock(&g_state_mutex);
	destroy_state(state);
	mutex_unlock(&g_state_mutex);
	return ret;
}

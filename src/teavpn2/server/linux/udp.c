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

/*
 * Each user session represents this struct.
 */
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

	_Atomic(bool)				is_authenticated;
	_Atomic(bool)				is_connected;
};

/*
 * Map for hashtable lookup (IPv4 only).
 */
struct sess_map4;
struct sess_map4 {
	/*
	 * @next is only used for collision handling.
	 */
	struct sess_map4			*next;
	struct udp_sess				*sess;
};

struct srv_state;

#define EPOLL_NR_EVENTS 10u

/*
 * Each worker thread when using EL_EPOLL represents this struct.
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
	struct sc_pkt				*pkt;
};

struct srv_state {
	/*
	 * @stop is true when the event loop needs to stop.
	 */
	volatile bool				stop;

	/*
	 * @in_emergency will be true in case we run out of
	 * buffer, or when we are in the similar urgent
	 * situation that needs more attention.
	 */
	volatile bool				in_emergency;

	/*
	 * @need_remove_iff determines whether we need to
	 * delete the virtual network interface.
	 */
	bool					need_remove_iff;

	/*
	 * @evt_loop determines what event loop type to use.
	 * Currently there are EL_EPOLL and EL_IO_URING.
	 */
	uint8_t					evt_loop;

	/*
	 * @udp_fd is the UDP socket file descriptor.
	 */
	int					udp_fd;

	/*
	 * @tun_fds is an array of TUN/TAP file descriptor.
	 */
	int					*tun_fds;

	/*
	 * Array of user sessions.
	 */
	struct udp_sess				*sess;

	/*
	 * Small hash table for session lookup after recvfrom().
	 */
	struct sess_map4			(*sess_map4)[0x100];
	struct tmutex				sess_map4_lock;

	/*
	 * @cfg is the application config.
	 */
	struct srv_cfg				*cfg;

	union {
		struct epoll_wrk		*epoll_threads;
	};

	/*
	 * Number of online threads.
	 */
	_Atomic(uint16_t)			nr_on_threads;

	/*
	 * Number of online sessions.
	 */
	_Atomic(uint16_t)			nr_on_sess;

	/*
	 * Stack to get unused UDP session index in O(1).
	 */
	struct bt_stack				sess_stk;
	struct tmutex				sess_stk_lock;

	/*
	 * @sig is the signal caught by the signal handler.
	 * If the signal handler is not called, @sig == -1.
	 */
	int					sig;
};

#define W_IP(CLIENT) 	((CLIENT)->str_src_addr), ((CLIENT)->src_port)
#define W_UN(CLIENT) 	((CLIENT)->username)
#define W_IU(CLIENT) 	W_IP(CLIENT), W_UN(CLIENT), ((CLIENT)->idx)
#define PRWIU 		"%s:%d (%s) (cli_idx=%hu)"

static DEFINE_MUTEX(g_state_mutex);
static struct srv_state *g_state = NULL;

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

static __cold int select_event_loop(struct srv_state *state,
				    struct srv_cfg *cfg)
{
	struct srv_cfg_sock *sock = &cfg->sock;
	const char *evtl = sock->event_loop;

	if ((evtl[0] == '\0') || (!strcmp(evtl, "epoll"))) {
		state->evt_loop = EL_EPOLL;
	} else if (!strcmp(evtl, "io_uring") ||
		   !strcmp(evtl, "io uring") ||
		   !strcmp(evtl, "iouring")  ||
		   !strcmp(evtl, "uring")) {
		state->evt_loop = EL_IO_URING;
	} else {
		pr_err("Invalid socket event loop: \"%s\"", evtl);
		return -EINVAL;
	}
	return 0;
}

static __cold int init_state(struct srv_state **state_p, struct srv_cfg *cfg)
	__must_hold(&g_state_mutex)
{
	struct srv_state *state;
	int *tun_fds;
	uint8_t i;
	int ret;

	if (unlikely(cfg->sys.thread_num < 1)) {
		pr_err("cfg->sys.thread_num must be at least 1, %hhu given",
			cfg->sys.thread_num);
		return -EINVAL;
	}

	if (unlikely(cfg->sock.max_conn < 1)) {
		pr_err("cfg->sock.max_conn must be at least 1, %hu given",
			cfg->sock.max_conn);
		return -EINVAL;
	}

	state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (unlikely(state == MAP_FAILED)) {
		ret = errno;
		pr_err("mmap(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = mlock(state, sizeof(*state));
	if (unlikely(ret)) {
		ret = -errno;
		pr_err("mlock(): " PRERF, PREAR(-ret));
		goto fail;
	}

	memset(state, 0, sizeof(*state));
	ret = select_event_loop(state, cfg);
	if (unlikely(ret))
		goto fail_unlock;

	tun_fds = calloc(cfg->sys.thread_num, sizeof(*tun_fds));
	if (unlikely(!tun_fds)) {
		ret = -ENOMEM;
		pr_err("calloc(): " PRERF, PREAR(ENOMEM));
		goto fail_unlock;
	}
	for (i = 0; i < cfg->sys.thread_num; i++)
		tun_fds[i] = -1;


	state->stop            = false;
	state->in_emergency    = false;
	state->need_remove_iff = false;
	state->udp_fd          = -1;
	state->tun_fds         = tun_fds;
	state->sess            = NULL;
	state->cfg             = cfg;
	atomic_store(&state->nr_on_threads, 0);
	state->sess_stk.arr    = NULL;
	state->sig             = -1;
	*state_p               = state;
	g_state                = state;
	return 0;

fail_unlock:
	munlock(state, sizeof(*state));
fail:
	munmap(state, sizeof(*state));
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
	const void *py = (const void *) &y;
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

	/*
	 * S
	 */
	non_block = (state->evt_loop != EL_IO_URING);
	type = SOCK_DGRAM | (non_block ? SOCK_NONBLOCK : 0);

	udp_fd = socket(AF_INET, type, 0);
	if (unlikely(udp_fd < 0)) {
		const char *q;
		ret = errno;
		q = non_block ? " | SOCK_NONBLOCK" : "";
		pr_err("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF, q,
			PREAR(ret));
		return -ret;
	}
	prl_notice(2, "UDP socket initialized successfully (fd=%d)", udp_fd);


	prl_notice(2, "Setting up socket configuration...");
	ret = socket_setup(udp_fd, state);
	if (unlikely(ret))
		goto out_err;


	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);
	prl_notice(2, "Binding UDP socket to %s:%hu...", sock->bind_addr,
		   sock->bind_port);


	ret = bind(udp_fd, (struct sockaddr *) &addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = -errno;
		pr_err("bind(): " PRERF, PREAR(-ret));
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
		pr_err("tun_alloc(\"%s\", %d): " PRERF, dev, flags,
			PREAR(-ret));
		return ret;
	}

	if (!non_block)
		return ret;

	tmp = fd_set_nonblock(ret);
	if (unlikely(tmp < 0)) {
		__sys_close(ret);
		pr_err("fd_set_nonblock(%d): " PRERF, ret, PREAR(-tmp));
		return tmp;
	}

	return ret;
}

static __cold int init_iface(struct srv_state *state)
{
	const short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	const char *dev = state->cfg->iface.dev;
	bool non_block;
	uint8_t i, nn;
	int *tun_fds;
	int ret = 0;

	if (unlikely(!dev || !*dev)) {
		pr_err("iface dev cannot be empty!");
		return -EINVAL;
	}

	prl_notice(2, "Initializing virtual network interface (%s)...", dev);
	tun_fds   = state->tun_fds;
	nn        = state->cfg->sys.thread_num;
	non_block = (state->evt_loop == EL_EPOLL);

	for (i = 0; i < nn; i++) {
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
		return -ENETDOWN;
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

static struct udp_sess *reset_session(struct udp_sess *sess, uint16_t i)
{
	memset(sess, 0, sizeof(*sess));
	sess->idx = i;
	return sess;
}

static __cold int init_session_array(struct srv_state *state)
{
	struct udp_sess *sess;
	size_t i, nn, len;
	int ret = 0;

	prl_notice(2, "Initializing session array...");

	nn   = state->cfg->sock.max_conn;
	len  = nn * sizeof(*sess);
	sess = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (unlikely(state == MAP_FAILED)) {
		ret = errno;
		pr_err("mmap(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = mlock(sess, len);
	if (unlikely(ret < 0)) {
		ret = -errno;
		pr_err("mlock(): " PRERF, PREAR(-ret));
		munmap(sess, len);
		return ret;
	}

	for (i = 0; i < nn; i++)
		reset_session(&sess[i], (uint16_t) i);

	state->sess = sess;
	return ret;
}

static __cold int init_session_stack(struct srv_state *state)
{
	uint16_t i, max_conn = state->cfg->sock.max_conn;
	int ret;

	prl_notice(4, "Initializing UDP session stack...");
	ret = mutex_init(&state->sess_stk_lock, NULL);
	if (unlikely(ret))
		return -ret;

	if (unlikely(!bt_stack_init(&state->sess_stk, max_conn)))
		return -errno;

#ifndef NDEBUG
	for (i = 0; i < 100; i++)
		bt_stack_test(&state->sess_stk);
#endif

	for (i = max_conn; i--;) {
		int32_t tmp = bt_stack_push(&state->sess_stk, (uint16_t) i);
		if (unlikely(tmp == -1)) {
			panic("Fatal bug in init_udp_session_stack!");
			__builtin_unreachable();
		}
	}

	return 0;
}

static __cold int init_session_map_ipv4(struct srv_state *state)
{
	const size_t map_len = sizeof(struct sess_map4) * 0x100ul * 0x100ul;
	struct sess_map4 (*sess_map4)[0x100];
	int ret;

	prl_notice(4, "Initializing UDP session map for IPv4...");
	ret = mutex_init(&state->sess_map4_lock, NULL);
	if (unlikely(ret))
		return -ret;

	sess_map4 = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (unlikely(sess_map4 == MAP_FAILED)) {
		ret = errno;
		pr_err("mmap(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = mlock(sess_map4, map_len);
	if (unlikely(ret)) {
		ret = errno;
		pr_err("mlock(): " PRERF, PREAR(ret));
		munmap(sess_map4, map_len);
		mutex_destroy(&state->sess_map4_lock);
		return -ret;
	}
	memset(sess_map4, 0, map_len);
	state->sess_map4 = sess_map4;
	return ret;
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

static __hot ssize_t do_recvfrom(int udp_fd, void *buf, size_t buflen,
				 struct sockaddr_in *addr, socklen_t *addr_len)
{
	return __sys_recvfrom(udp_fd, buf, buflen, 0, (struct sockaddr *) addr,
			      addr_len);
}

static struct sess_map4 *get_sess_map4(struct sess_map4 (*sess_map4)[0x100],
				       uint32_t addr)
{
	size_t idx1, idx2;
	idx1 = (addr >> 0u) & 0xffu;
	idx2 = (addr >> 8u) & 0xffu;
	return &sess_map4[idx1][idx2];
}

static int insert_udp_sess_map4(struct srv_state *state, uint32_t addr,
				struct udp_sess *sess)
	__acquires(&state->sess_map4_lock)
	__releases(&state->sess_map4_lock)
{
	struct sess_map4 *iter;
	struct sess_map4 *next;
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
	atomic_store_explicit(&ret->is_connected, true, memory_order_relaxed);
	atomic_fetch_add_explicit(&state->nr_on_sess, 1, memory_order_relaxed);
	addr = htonl(addr);
	WARN_ON(!inet_ntop(AF_INET, &addr, ret->str_src_addr,
			   sizeof(ret->str_src_addr)));
	return ret;
}

static __hot struct udp_sess *lookup_udp_sess_map4(struct srv_state *state,
						   uint32_t addr, uint16_t port)
	__acquires(&state->sess_map4_lock)
	__releases(&state->sess_map4_lock)
{
	struct udp_sess *ret = NULL;
	struct sess_map4 *iter;

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

		ret  = NULL;
		iter = iter->next;
	} while (iter);
	mutex_unlock(&state->sess_map4_lock);
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
	static const size_t expected_len = sizeof(*hand);
	struct teavpn2_version *cur = &hand->cur;
	int ret = -EBADMSG;

	if (len < (PKT_MIN_LEN + expected_len)) {
		snprintf(ctx->rej_msg, sizeof(ctx->rej_msg),
			 "Invalid handshake packet length from " PRWIU
			 " (expected at least %zu bytes; actual = %zu bytes)",
			 W_IU(sess), (PKT_MIN_LEN + expected_len), len);
		ctx->rej_reason = TSRV_HREJECT_INVALID;
		goto out;
	}

	cli_pkt->len = ntohs(cli_pkt->len);
	if ((size_t) cli_pkt->len != expected_len) {
		snprintf(ctx->rej_msg, sizeof(ctx->rej_msg),
			 "Invalid handshake packet length from " PRWIU
			 " (expected = %zu; actual: cli_pkt->len = %hu)",
			 W_IU(sess), expected_len, cli_pkt->len);
		ctx->rej_reason = TSRV_HREJECT_INVALID;
		goto out;
	}

	if (cli_pkt->type != TCLI_PKT_HANDSHAKE) {
		snprintf(ctx->rej_msg, sizeof(ctx->rej_msg),
			 "Invalid first packet type from " PRWIU
			 " (expected = TCLI_PKT_HANDSHAKE (%u); actual = %hhu)",
			 W_IU(sess), TCLI_PKT_HANDSHAKE, cli_pkt->type);
		ctx->rej_reason = TSRV_HREJECT_INVALID;
		goto out;
	}

	/* For printing safety! */
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
		ctx->rej_reason = TSRV_HREJECT_VERSION_NOT_SUPPORTED;
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int _el_epoll_handle_new_conn(struct epoll_wrk *thread,
				     struct udp_sess *sess)
{
	struct sc_pkt *pkt = thread->pkt;
	struct handshake_ctx hctx;
	int ret;

	ret = check_client_handshake(&pkt->cli, pkt->len, &hctx, sess);
	if (unlikely(ret)) {
		/*
		 * Handshake failed, drop the client session!
		 */
		// do_drop();

		if (ret == -EBADMSG) {
			prl_notice(2, "%s", hctx.rej_msg);

			/*
			 * If the handle_client_handshake() returns -EBADMSG,
			 * this means the client has sent bad handshake packet.
			 * It's not our fault, so return 0 as we are still fine.
			 */
			ret = 0;
		}
	}
	return ret;
}

static int el_epoll_handle_new_conn(struct epoll_wrk *thread,
				    uint32_t addr, uint16_t port,
				    struct sockaddr_in *saddr)
{
	struct udp_sess *sess;
	int ret = 0;

	/*
	 * Only create a new session when a new client
	 * sends a handshake pakcet. Otherwise, ignore
	 * it.
	 */
	if (thread->pkt->cli.type != TCLI_PKT_HANDSHAKE)
		return 0;

	sess = create_udp_sess4(thread->state, addr, port, saddr);
	if (IS_ERR(sess)) {
		ret = PTR_ERR(sess);

		/*
		 * Don't fail if the failure reason is:
		 * "session array is full".
		 */
		return (ret == -EAGAIN) ? 0 : ret;
	}

	/*
	 * If we succeed in calling create_udp_sess4(), we must have it
	 * on the map. If we don't have, then it's a bug!
	 */
	BUG_ON(lookup_udp_sess_map4(thread->state, addr, port) != sess);
	return _el_epoll_handle_new_conn(thread, sess);
}

static __hot int _el_epoll_handle_event_udp(struct epoll_wrk *thread,
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
		return el_epoll_handle_new_conn(thread, addr, port, saddr);

	return ret;
}

static __hot int el_epoll_handle_event_udp(struct epoll_wrk *thread, int fd)
{
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);
	size_t buflen;
	ssize_t ret;
	void *buf;
	
	buf    = &thread->pkt->srv;
	buflen = sizeof(thread->pkt->srv);
	ret    = do_recvfrom(fd, buf, buflen, &saddr, &saddr_len);
	if (unlikely(ret <= 0)) {

		if (ret == -EAGAIN)
			/*
			 * Handle non-blocking socket behavior.
			 * Don't treat this as an error.
			 */
			return 0;

		if (ret == 0) {
			pr_err("recvfrom() returned 0, network down?");
			return -ENETDOWN;
		}

		pr_err("recvfrom(): " PRERF, PREAR((int) -ret));
		return ret;
	}
	prl_notice(4, "recvfrom(): %zd bytes", ret);
	thread->pkt->len = (size_t) ret;
	return _el_epoll_handle_event_udp(thread, &saddr);
}

static __hot int el_epoll_handle_event_tun(struct epoll_wrk *thread, int fd)
{
	const size_t read_size = sizeof(thread->pkt->srv.__raw);
	void *buf = thread->pkt->srv.__raw;
	ssize_t read_ret;

	read_ret = __sys_read(fd, buf, read_size);
	if (unlikely(read_ret < 0)) {
		if (read_ret == -EAGAIN)
			return 0;
		pr_err("read(tun_fd) (fd=%d): " PRERF, fd,
		       PREAR((int) -read_ret));
		return (int) read_ret;
	}
	pr_notice("[thread=%hu] read(tun_fd=%d) = %zd bytes", thread->idx,
		  fd, read_ret);
	return 0;
}

static __hot int el_epoll_handle_event(struct epoll_wrk *thread,
				       struct epoll_event *event)
{
	struct srv_state *state = thread->state;
	int fd = event->data.fd;
	int ret;

	if (fd == state->udp_fd)
		ret = el_epoll_handle_event_udp(thread, fd);
	else
		ret = el_epoll_handle_event_tun(thread, fd);

	/* TODO: Handle specific case before return. */
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
		if (likely(ret == -EINTR)) {
			prl_notice(2, "[thread=%hu] Interrupted!", thread->idx);
			return 0;
		}
		pr_err("[thread=%u] epoll_wait(): " PRERF, thread->idx,
		       PREAR(-ret));
	}
	return ret;
}

static __hot int el_epoll_run_event_loop(struct epoll_wrk *thread)
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
		tmp = el_epoll_handle_event(thread, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}

static noinline __cold void el_epoll_wait_threads(struct epoll_wrk *thread)
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

static noinline void *el_epoll_wrk(void *thread_p)
{
	struct epoll_wrk *thread = thread_p;
	struct srv_state *state = thread->state;
	int ret = 0;

	atomic_fetch_add(&state->nr_on_threads, 1);
	atomic_store(&thread->is_on, true);
	el_epoll_wait_threads(thread);

	while (likely(!state->stop)) {
		ret = el_epoll_run_event_loop(thread);
		if (unlikely(ret))
			break;
	}

	prl_notice(2, "epoll_threads[%zu] is exiting...", (size_t) thread->idx);
	atomic_store(&thread->is_on, false);
	atomic_fetch_sub(&state->nr_on_threads, 1);
	return (void *) (intptr_t) ret;
}

static __cold int el_epoll_init_threads(struct srv_state *state)
{
	size_t nn = (size_t) state->cfg->sys.thread_num;
	struct epoll_wrk *threads;
	struct epoll_wrk *thread;
	size_t map_size;
	size_t i;
	int ret;

	if (WARN_ON(nn < 1)) {
		nn = 1;
		state->cfg->sys.thread_num = 1;
	}

	map_size = nn * sizeof(*threads);
	threads  = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (unlikely(!threads)) {
		ret = errno;
		pr_err("mmap(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = mlock(threads, map_size);
	if (unlikely(ret)) {
		ret = errno;
		munmap(threads, map_size);
		pr_err("mlock():" PRERF, PREAR(ret));
		return -ret;
	}
	state->epoll_threads = threads;
	memset(threads, 0, map_size);

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

		/*
		 * At this point, if the allocation fails when i > 0,
		 * the caller is responsible to clean it up.
		 */
		thread->pkt = mmap(NULL, sizeof(*thread->pkt),
				   PROT_READ | PROT_WRITE,
				   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (unlikely(thread->pkt == MAP_FAILED)) {
			ret = errno;
			pr_err("mmap():" PRERF, PREAR(ret));
			return -ret;
		}

		ret = mlock(thread->pkt, sizeof(*thread->pkt));
		if (unlikely(ret)) {
			ret = errno;
			munmap(thread->pkt, sizeof(*thread->pkt));
			thread->pkt = NULL;
			pr_err("mlock():" PRERF, PREAR(ret));
			return -ret;
		}

		memset(thread->pkt, 0, sizeof(*thread->pkt));
	}

	return 0;
}

static __cold int el_epoll_register_tun_fds(struct srv_state *state,
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

static __cold int el_epoll_init_epoll(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	size_t i, nn = (size_t) state->cfg->sys.thread_num;

	prl_notice(2, "Initializing epoll fd...");
	for (i = 0; i < nn; i++) {
		int ret;
		ret = epoll_create(255);
		if (unlikely(ret < 0)) {
			/*
			 * If we fail at i > 0, the caller is responsible
			 * to close the active epoll fds.
			 */
			ret = -errno;
			pr_err("epoll_create(): " PRERF, PREAR(-ret));
			return ret;
		}

		threads[i].fd = ret;
		threads[i].timeout = 1000;

		ret = el_epoll_register_tun_fds(state, &threads[i]);
		if (unlikely(ret))
			return ret;

		prl_notice(5, "epoll_threads[%zu].fd = %d", i, ret);
	}
	return 0;
}

static __cold int el_epoll_spawn_thread(struct epoll_wrk *thread)
{
	char tname[sizeof("epoll-wrk-xxxxx")];
	int ret;

	ret = pthread_create(&thread->thread, NULL, el_epoll_wrk, thread);
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

static __cold int el_epoll_spawn_threads(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	size_t i, nn = (size_t) state->cfg->sys.thread_num;

	/*
	 * @threads[0] is executed by the main thread,
	 * don't spawn an LWP for it.
	 */
	for (i = 1; i < nn; i++) {
		int ret;

		prl_notice(2, "Spawning threads[%zu]...", i);
		ret = el_epoll_spawn_thread(&threads[i]);
		if (unlikely(ret))
			return ret;
	}

	return 0;
}

static void el_epoll_join_threads(struct srv_state *state)
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
			pr_err("pthread_kill(): " PRERF, PREAR(err));
	}


	do {
		r = atomic_load(nrp);
		if (r) {
			pr_notice("Waiting for %hu thread(s) to exit...", r);
			usleep(500000);
		}
	} while (r);
}

static void el_epoll_destroy(struct srv_state *state)
{
	struct epoll_wrk *threads = state->epoll_threads;
	size_t i, nn = (size_t) state->cfg->sys.thread_num;

	if (!threads)
		return;

	el_epoll_join_threads(state);

	for (i = 0; i < nn; i++) {
		struct epoll_wrk *thread = &threads[i];
		int fd;

		if (thread->pkt) {
			munlock(thread->pkt, sizeof(*thread->pkt));
			munmap(thread->pkt, sizeof(*thread->pkt));
			thread->pkt = NULL;
		}

		fd = thread->fd;
		if (fd == -1)
			continue;
		prl_notice(2, "Closing epoll_threads[%zu] (fd=%d)...", i, fd);
		__sys_close(fd);
	}
	munlock(threads, nn * sizeof(*threads));
	munmap(threads, nn * sizeof(*threads));
}

static int el_epoll_run_server(struct srv_state *state)
{
	void *ret_p;
	int ret;

	ret = el_epoll_init_threads(state);
	if (unlikely(ret))
		goto out;
	ret = el_epoll_init_epoll(state);
	if (unlikely(ret))
		goto out;
	ret = el_epoll_spawn_threads(state);
	if (unlikely(ret))
		goto out;
	ret_p = el_epoll_wrk(&state->epoll_threads[0]);
	ret   = (int) (intptr_t) ret_p;
out:
	el_epoll_destroy(state);
	return ret;
}

static int run_server_event_loop(struct srv_state *state)
{
	switch (state->evt_loop) {
	case EL_EPOLL:
		return el_epoll_run_server(state);
	case EL_IO_URING:
		pr_err("run_client_event_loop() with io_uring: " PRERF,
			PREAR(EOPNOTSUPP));
		return -EOPNOTSUPP;
	}

	pr_err("Invalid event loop type: %hhu", state->evt_loop);
	return -EINVAL;
}

static __cold void destroy_session_stack(struct srv_state *state)
{
	if (!state->sess_stk.arr)
		return;

	mutex_lock(&state->sess_stk_lock);
	bt_stack_destroy(&state->sess_stk);
	mutex_unlock(&state->sess_stk_lock);
	mutex_destroy(&state->sess_stk_lock);
}

static __cold void destroy_session_array(struct srv_state *state)
{
	struct udp_sess *sess;
	size_t i, nn, len;

	if (!state->sess)
		return;

	sess = state->sess;
	nn   = (size_t) state->cfg->sock.max_conn;
	len  = nn * sizeof(*sess);
	for (i = 0; i < nn; i++) {
		/* TODO: Send close packet to the active clients. */
	}

	munlock(sess, len);
	munmap(sess, len);
	state->sess = NULL;
}

static __cold void destroy_session_map_ipv4(struct srv_state *state)
{
	struct sess_map4 (*sess_map4)[0x100] = state->sess_map4;
	const size_t map_len = sizeof(struct sess_map4) * 0x100u * 0x100u;

	if (!sess_map4)
		return;

	mutex_lock(&state->sess_map4_lock);
	munlock(sess_map4, map_len);
	munmap(sess_map4, map_len);
	state->sess_map4 = NULL;
	mutex_unlock(&state->sess_map4_lock);
	mutex_destroy(&state->sess_map4_lock);
}

static __cold void destroy_tun_fds(struct srv_state *state)
{
	int *tun_fds = state->tun_fds;
	uint8_t i, nn;

	if (!tun_fds)
		return;

	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		if (tun_fd == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fd);
		__sys_close(tun_fd);
	}
	free(tun_fds);
	state->tun_fds = NULL;
}

static __cold void destroy_state(struct srv_state *state)
	__must_hold(&g_state_mutex)
{
	g_state = NULL;
	destroy_session_stack(state);
	destroy_session_map_ipv4(state);
	destroy_session_array(state);
	destroy_tun_fds(state);
	munlock(state, sizeof(*state));
	munmap(state, sizeof(*state));
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
	ret = run_server_event_loop(state);

out_del_sig:
	set_signal_handler(false);
out:
	mutex_lock(&g_state_mutex);
	destroy_state(state);
	mutex_unlock(&g_state_mutex);
	return ret;
}

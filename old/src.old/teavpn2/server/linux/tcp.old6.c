// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TCP handler for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <alloca.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/cpu.h>
#include <teavpn2/base.h>
#include <teavpn2/auth.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/tcp.h>
#include <teavpn2/net/tcp_pkt.h>
#include <teavpn2/server/tcp_slot_stack.h>

/* Shut the clang up! */
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Weverything"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


/*
 * We tolerate small number of errors
 */
#define CLIENT_MAX_ERR		(0x0fu)
#define SERVER_MAX_ERR		(0x0fu)


#define EPOLL_INPUT_EVT		(EPOLLIN | EPOLLPRI)
#define EPOLL_MAP_SIZE		(0xffffu)
#define EPOLL_MAP_TO_NOP	(0x0000u)
#define EPOLL_MAP_TO_TCP	(0x0001u)
#define EPOLL_MAP_TO_TUN	(0x0002u)
#define EPOLL_MAX_MAP           (EPOLL_MAP_SIZE - 1u)
/*
 * EPOLL_MAPCL_SHIFT is a shift for `map to` client file descriptors.
 * This value must be the number of `EPOLL_MAP_TO_*` constants.
 */
#define EPOLL_MAPCL_SHIFT	(0x0003u)


#define IP_MAP_SHIFT		(0x00001u)	/* Preserve IP_MAP_TO_NOP     */
#define IP_MAP_TO_NOP		(0x00000u)	/* Represents unused map slot */


/* Macros for printing  */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


typedef enum _gt_cli_evt_t {
	HCE_OK = 0,
	HCE_ERR = 1,
	HCE_CLOSE = 2
} gt_cli_evt_t;


typedef enum _clslot_state_t {
	CT_DISCONNECTED = 0,
	CT_NEW		= 1,
	CT_ESTABLISHED	= 2,
	CT_NOSYNC	= 3,
} clslot_state_t;


struct srv_mutex {
	pthread_mutex_t		mutex;
	bool			need_destroy;
	struct_pad(0, sizeof(pthread_mutex_t) - sizeof(bool));
};


struct srv_client_slot {
	bool			is_auth;
	uint8_t			err_c;
	struct_pad(0, 2);
	clslot_state_t		state;

	/*
	 * Client file descriptor
	 */
	int			cli_fd;
	/*
	 * send() and recv() counter
	 */
	uint32_t		send_c;
	uint32_t		recv_c;
	/*
	 * To find the index in client slots which
	 * refers to "this" client struct, for example:
	 *    
	 *   state->clients[slot_idx]
	 */
	uint16_t		slot_idx;
	uint16_t		src_port;
	char			src_ip[IPV4_L];
	char			uname[64];
	SSL			*ssl;
	uint32_t		private_ip;
	struct_pad(1, 4);
	size_t			recv_s;
	utcli_pkt_t		recv_buf;
};


struct srv_tcp_thread {
	int			epoll_fd;
	int			epoll_timeout;
	int			epoll_max_events;
	uint16_t		epoll_queue_n;
	uint8_t			thread_num;
	bool			is_active;

	struct srv_tcp_state	*state;
	struct epoll_event	*events;
	pthread_t		thread;
	struct srv_mutex	epoll_mut;
};


struct srv_tcp_state {
	bool			stop_event_loop;
	bool			need_ssl_cleanup;
	bool			need_iface_down;
	uint8_t			err_c;

	uint32_t		accept_c;
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	int			tun_fd;
	int			tcp_fd;

	uint64_t		up_bytes;
	uint64_t		down_bytes;

	SSL_CTX			*ssl_ctx;
	struct srv_cfg		*cfg;
	struct srv_tcp_thread	*threads;
	struct srv_client_slot	*clients;
	uint16_t		*epoll_map;
	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`.
	 *
	 * The value of ip_map[i][j] is an index of `clients`
	 * slot in this struct. So you can access it like this:
	 * ```c
	 *    struct client_slot *client;
	 *    uint16_t map_to = ip_map[i][j];
	 *
	 *    if (map_to != IP_MAP_TO_NOP) {
	 *        client = &state->clients[map_to - IP_MAP_SHIFT];
	 *
	 *        // use client->xxxx here
	 *
	 *    } else {
	 *        // map is not mapped to client slot
	 *    }
	 * ```
	 */
	uint16_t		(*ip_map)[256];
	/*
	 * To which thread we are going to plug the client
	 * epoll queue?
	 */
	uint8_t			accept_plug_to;
	struct_pad(0, 1);
	struct iface_cfg	siff;
	struct_pad(1, 4);
	struct tcp_slot_stack	cl_stack;
	struct srv_mutex	cl_slot_mut;
	int			intr_sig;
	struct_pad(2, 4);
	cpu_set_t		affinity;
	utsrv_pkt_t		send_buf;
};


static struct srv_tcp_state *g_state;


static inline int mutex_lock(struct srv_mutex *mut)
{
	return pthread_mutex_lock(&mut->mutex);
}


static inline int mutex_unlock(struct srv_mutex *mut)
{
	return pthread_mutex_unlock(&mut->mutex);
}


static inline int mutex_init(struct srv_mutex *mut)
{
	int ret;
	int err;

	mut->need_destroy = false;
	ret = pthread_mutex_init(&mut->mutex, NULL);
	if (unlikely(ret != 0)) {
		err = (ret > 0) ? ret : -ret;
		pr_err("pthread_mutex_init(): " PRERF, PREAR(err));
		return -err;
	}
	mut->need_destroy = true;

	return ret;
}


static inline void mutex_destroy(struct srv_mutex *mut)
{
	if (likely(mut->need_destroy)) {
		pthread_mutex_destroy(&mut->mutex);
		mut->need_destroy = false;
	}
}


static void handle_interrupt(int sig)
{
	struct srv_tcp_state *state = g_state;

	if (unlikely(state->stop_event_loop == true))
		return;

	state->intr_sig = sig;
	state->stop_event_loop = true;
	putchar('\n');
}


static void *calloc_wrp(size_t nmemb, size_t size)
{
	void *ret;
	ret = calloc(nmemb, size);
	if (unlikely(ret == NULL)) {
		int err = errno;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}

	return ret;
}


static int init_state_ip_map(struct srv_tcp_state *state)
{
	uint16_t (*ip_map)[256];

	ip_map = calloc_wrp(256, sizeof(*ip_map));
	if (unlikely(ip_map == NULL))
		return -ENOMEM;

	for (uint16_t i = 0; i < 256; i++) {
		for (uint16_t j = 0; j < 256; j++) {
			ip_map[i][j] = IP_MAP_TO_NOP;
		}
	}

	state->ip_map = ip_map;
	return 0;
}

/*
 * Caller is responsible to maintain the slot_idx
 */
static void reset_client_slot(struct srv_client_slot *client,
			      uint16_t slot_idx)
{
	client->is_auth    = false;
	client->err_c      = 0;
	client->state      = CT_DISCONNECTED;

	client->cli_fd     = -1;

	client->send_c     = 0;
	client->recv_c     = 0;

	client->slot_idx   = slot_idx;

	client->src_port   = 0;
	client->src_ip[0]  = '\0';
	client->uname[0]   = '_';
	client->uname[1]   = '\0';
	client->private_ip = 0;
	client->recv_s     = 0;

	if (client->ssl != NULL) {
		SSL_shutdown(client->ssl);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
}


static int init_state_client_slot(struct srv_tcp_state *state)
{
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct srv_client_slot *clients;

	clients = calloc_wrp(max_conn, sizeof(*clients));
	if (unlikely(clients == NULL))
		return -ENOMEM;

	while (max_conn--)
		reset_client_slot(&clients[max_conn], max_conn);

	state->clients = clients;
	return 0;
}


static int init_state_epoll_map(struct srv_tcp_state *state)
{
	uint16_t *epoll_map;

	epoll_map = calloc_wrp(EPOLL_MAP_SIZE, sizeof(*epoll_map));
	if (unlikely(epoll_map == NULL))
		return -ENOMEM;

	for (uint16_t i = 0; i < EPOLL_MAP_SIZE; i++) {
		epoll_map[i] = EPOLL_MAP_TO_NOP;
	}
	state->epoll_map = epoll_map;
	return 0;
}


static int init_state_tss_stack(struct srv_tcp_state *state)
{
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct tcp_slot_stack *cl_stack = &state->cl_stack;

	if (unlikely(tss_init(cl_stack, max_conn) == NULL))
		return -ENOMEM;

	while (likely(max_conn--))
		tss_push(cl_stack, max_conn);

	TASSERT(tss_count(cl_stack) == state->cfg->sock.max_conn);
	TASSERT(tss_capacity(cl_stack) == state->cfg->sock.max_conn);

	return 0;
}

static int init_state(struct srv_tcp_state *state)
{
	uint8_t num_of_threads = state->cfg->num_of_threads;
	if (unlikely(num_of_threads == 0)) {
		pr_err("Number of threads cannot be zero!");
		return -1;
	}

	state->stop_event_loop    = false;
	state->need_ssl_cleanup   = false;
	state->need_iface_down    = false;
	state->err_c              = 0;

	state->accept_c           = 0;
	state->read_tun_c         = 0;
	state->write_tun_c        = 0;

	state->tun_fd             = -1;
	state->tcp_fd             = -1;

	state->up_bytes           = 0;
	state->down_bytes         = 0;

	state->ssl_ctx            = NULL;
	state->threads            = NULL;
	state->clients            = NULL;
	state->epoll_map          = NULL;
	state->ip_map             = NULL;
	state->cl_stack.arr       = NULL;

	state->accept_plug_to     = (num_of_threads > 0) ? 1 : 0;
	state->intr_sig           = -1;
	memset(&state->siff, 0, sizeof(state->siff));
	memset(&state->affinity, 0, sizeof(state->affinity));

	if (unlikely(init_state_ip_map(state) < 0))
		return -1;
	if (unlikely(init_state_client_slot(state) < 0))
		return -1;
	if (unlikely(init_state_epoll_map(state) < 0))
		return -1;
	if (unlikely(init_state_tss_stack(state) < 0))
		return -1;
	if (unlikely(mutex_init(&state->cl_slot_mut) < 0))
		return -1;

	return 0;
}


static int init_iface(struct srv_tcp_state *state)
{
	int tun_fd;
	struct iface_cfg *i = &state->siff;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	tun_fd = tun_alloc(j->dev, IFF_TUN | IFF_NO_PI);
	if (unlikely(tun_fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(tun_fd) < 0))
		goto out_err;

	memset(i, 0, sizeof(struct iface_cfg));
	sane_strncpy(i->dev, j->dev, sizeof(i->dev));
	sane_strncpy(i->ipv4, j->ipv4, sizeof(i->ipv4));
	sane_strncpy(i->ipv4_netmask, j->ipv4_netmask, sizeof(i->ipv4_netmask));
	i->mtu = j->mtu;

	if (unlikely(!teavpn_iface_up(i))) {
		pr_err("Cannot raise virtual network interface up");
		goto out_err;
	}

	if (unlikely((uint32_t)tun_fd > EPOLL_MAX_MAP)) {
		pr_err("tun_fd is too big (tun_fd=%d, EPOLL_MAX_MAP=%u)",
		       tun_fd, EPOLL_MAX_MAP);
		goto out_err;
	}

	state->tun_fd = tun_fd;
	state->need_iface_down = true;
	state->epoll_map[tun_fd] = EPOLL_MAP_TO_TUN;
	return 0;

out_err:
	close(tun_fd);
	return -1;
}


static int init_openssl(struct srv_tcp_state *state)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	state->need_ssl_cleanup = true;
	return 0;
}


static SSL_CTX *create_ssl_context()
{
	int err;
	SSL_CTX *ctx;
	const SSL_METHOD *method;

	method = SSLv23_server_method();
	ctx    = SSL_CTX_new(method);
	if (unlikely(!ctx)) {
		err = errno;
		pr_err("Unable to create SSL context: " PRERF, PREAR(err));
		return NULL;
	}

	return ctx;
}


static int configure_ssl_context(SSL_CTX *ssl_ctx, struct srv_tcp_state *state)
{
	int retval;
	unsigned long err;
	const char *cert, *key;
	struct srv_cfg *cfg = state->cfg;

	cert = cfg->sock.ssl_cert;
	key  = cfg->sock.ssl_priv_key;

	if (unlikely(cert == NULL)) {
		pr_err("Missing sock->ssl_cert " PRERF, PREAR(EFAULT));
		return -1;
	}

	if (unlikely(key == NULL)) {
		pr_err("Missing sock->ssl_priv_key " PRERF, PREAR(EFAULT));
		return -1;
	}

	retval = SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
	if (unlikely(retval <= 0)) {
		err = ERR_get_error();
		pr_err("SSL_CTX_use_certificate_file(\"%s\"): "
		       "[%lu]:[%s]:[%s]:[%s]",
		       key,
		       err,
		       ERR_lib_error_string(err),
		       ERR_func_error_string(err),
		       ERR_reason_error_string(err));
		return -1;
	}

	retval = SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
	if (unlikely(retval <= 0)) {
		err = ERR_get_error();
		pr_err("SSL_CTX_use_PrivateKey_file(\"%s\"): "
		       "[%lu]:[%s]:[%s]:[%s]",
		       key,
		       err,
		       ERR_lib_error_string(err),
		       ERR_func_error_string(err),
		       ERR_reason_error_string(err));
		return -1;
	}

	return 0;
}


static int init_ssl_context(struct srv_tcp_state *state)
{
	SSL_CTX *ssl_ctx;

	ssl_ctx = create_ssl_context();
	if (unlikely(ssl_ctx == NULL))
		return -1;

	if (unlikely(configure_ssl_context(ssl_ctx, state) < 0)) {
		SSL_CTX_free(ssl_ctx);
		return -1;
	}

	state->ssl_ctx = ssl_ctx;
	return 0;
}


static int set_socket_so_incoming_cpu(int tcp_fd, struct srv_tcp_state *state)
{
	int first_isset = -1, second_isset = -1, incoming_cpu = -1;
	const void *ptr = (const void *)&incoming_cpu;
	socklen_t len = sizeof(incoming_cpu);

	/*
	 * Take second_isset CPU, if there is no second_isset CPU,
	 * then use first_isset CPU
	 */
	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &state->affinity))
			continue;
		
		if (first_isset == -1) {
			first_isset = i;
		} else
		if (second_isset == -1) {
			second_isset = i;
		} else {
			break;
		}
	}

	prl_notice(6, "first_isset CPU = %d", first_isset);
	prl_notice(6, "second_isset CPU = %d", second_isset);

	/* We have second_isset CPU */
	if (second_isset != -1) {
		incoming_cpu = second_isset;
		goto out_set;
	}

	/*
	 * We don't have second_isset CPU, but we have
	 * fisrt_isset CPU.
	 */
	if (first_isset != -1) {
		incoming_cpu = first_isset;
		goto out_set;
	}

	/*
	 * Wait what?
	 * We don't have CPU affinity at all?!
	 */
	return 0;
out_set:
	return setsockopt(tcp_fd, SOL_SOCKET, SO_INCOMING_CPU, ptr, len);
}


static int socket_setup(int tcp_fd, struct srv_tcp_state *state)
{
	int y;
	int err;
	int retval;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;

	y = 1;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	retval = setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(retval < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}

	y = 6;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}

	y = 50000;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	retval = set_socket_so_incoming_cpu(tcp_fd, state);
	if (unlikely(retval < 0)) {
		lv  = "SOL_SOCKET";
		on  = "SO_INCOMING_CPU";
		err = errno;

		/*
		 * SO_INCOMING_CPU is not mandatory, so
		 * if it fails, keep the success state.
		 */
		pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on,
		       PREAR(err));
		retval = 0;
	}


	/*
	 * Use cfg to set some socket options.
	 */
	(void)cfg;
	return retval;
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return retval;
}


static int init_socket(struct srv_tcp_state *state)
{
	int err;
	int tcp_fd;
	int retval;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;

	prl_notice(0, "Creating TCP socket...");
	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(tcp_fd < 0)) {
		err = errno;
		pr_err("socket(): " PRERF, PREAR(err));
		return -1;
	}

	prl_notice(0, "Setting socket file descriptor up...");
	retval = socket_setup(tcp_fd, state);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);

	retval = bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(retval < 0)) {
		err = errno;
		pr_err("bind(): " PRERF, PREAR(err));
		goto out_err;
	}

	retval = listen(tcp_fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		pr_err("listen(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = tcp_fd;
	prl_notice(0, "Listening on %s:%d...", sock->bind_addr,
		   sock->bind_port);

	state->epoll_map[tcp_fd] = EPOLL_MAP_TO_TCP;
	return 0;
out_err:
	close(tcp_fd);
	return -1;
}


static int exec_epoll_wait(int epoll_fd, struct epoll_event *events,
			   int max_events, int timeout)
{
	int err;
	int ret;

	ret = epoll_wait(epoll_fd, events, max_events, timeout);
	if (unlikely(ret == 0)) {
		/*
		 * epoll_wait reaches its timeout
		 */
		return 0;
	}

	if (unlikely(ret < 0)) {
		err = errno;
		if (err == EINTR) {
			pr_notice("Interrupted!");
			return 0;
		}
		pr_err("epoll_wait(%d) " PRERF, epoll_fd, PREAR(err));
		return -1;
	}

	return ret;
}


static ssize_t handle_iface_read(int tun_fd, struct srv_tcp_state *state)
{
	int err;
	ssize_t read_ret;
	tsrv_pkt_t *srv_pkt;

	state->read_tun_c++;

	srv_pkt  = state->send_buf.__pkt_chk;
	read_ret = read(tun_fd, srv_pkt->raw_data, 4096);
	if (unlikely(read_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return 0;
		pr_err("read(fd=%d) from tun_fd " PRERF, tun_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] read(fd=%d) %zd bytes from tun_fd",
		   state->read_tun_c, tun_fd, read_ret);

	// route_packet(state, srv_pkt, (size_t)read_ret);
	return read_ret;
}


static int handle_tun_event(int tun_fd, struct srv_tcp_state *state,
			    uint32_t revents)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask)) {
		pr_err("TUN/TAP error");
		return -1;
	}

	return (int)handle_iface_read(tun_fd, state);
}


static const char *resolve_new_client_ip(struct sockaddr_in *saddr,
					 char *ip_buf)
{
	int err;
	const char *ret;

	/* Get readable source IP address */
	ret = inet_ntop(AF_INET, &saddr->sin_addr, ip_buf, IPV4_L);
	if (unlikely(ret == NULL)) {
		err = errno;
		err = err ? err : EINVAL;
		pr_err("inet_ntop(): " PRERF, PREAR(err));
		return NULL;
	}

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
		return -1;
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


static int plug_to_thread_epoll(int cli_fd, struct srv_tcp_thread *thread)
{
	int ret;
	ret = epoll_add(thread->epoll_fd, cli_fd, EPOLL_INPUT_EVT);
	if (unlikely(ret < 0))
		return -1;
	return 0;
}


static bool plug_to_client_slot(int cli_fd, const char *src_ip,
				uint16_t src_port,
				struct srv_tcp_state *state)
{
	SSL *ssl;
	bool ret;
	uint16_t idx;
	int32_t ret_idx;
	unsigned long err;
	uint8_t ti, num_of_threads;
	struct srv_client_slot *client;
	struct srv_tcp_thread *thread, *threads = state->threads;

	mutex_lock(&state->cl_slot_mut);
	ret_idx = tss_pop(&state->cl_stack);
	if (unlikely(ret_idx == -1)) {
		prl_notice(0, "Client slot is full, can't accept connection");
		ret = false;
		goto out;
	}

	idx            = (uint16_t)ret_idx;
	ti             = state->accept_plug_to;
	thread         = &threads[ti];
	num_of_threads = state->cfg->num_of_threads;

	if (unlikely(plug_to_thread_epoll(cli_fd, thread) < 0)) {
		pr_err("Cannot accept new connection from %s:%u because of "
		       "error on epoll_add()", src_ip, src_port);
		ret = false;
		goto out;
	}
	thread->epoll_queue_n++;

	/* `num_of_threads - 1` is the last index of `state->threads` */
	if (num_of_threads > 1) {
		if ((num_of_threads - 1) == ti)
			ti = 1;
		else
			ti++;
		state->accept_plug_to = ti;
	} else {
		/* Don't change anything, we only have single thread. */
	}

	if (unlikely((uint32_t)cli_fd > EPOLL_MAP_SIZE)) {
		pr_err("Client file descriptor is too big (cli_fd = %d; "
		       "EPOLL_MAP_SIZE = %u) from %s:%u", cli_fd,
		       EPOLL_MAP_SIZE, src_ip, src_port);
		ret = false;
		goto out;
	}

	TASSERT(state->epoll_map[cli_fd] == EPOLL_MAP_TO_NOP);

	/*
	 * Map the FD to translate to idx later
	 */
	state->epoll_map[cli_fd] = idx + EPOLL_MAPCL_SHIFT;
	client = &state->clients[idx];
	client->state    = CT_NEW;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;
	sane_strncpy(client->src_ip, src_ip, IPV4_L);

	prl_notice(0, "New connection from " PRWIU " (fd:%d)", W_IU(client),
		   cli_fd);

	ret = true;
out:
	mutex_unlock(&state->cl_slot_mut);
	if (ret == false)
		return ret;

	ssl = SSL_new(state->ssl_ctx);
	if (unlikely(ssl == NULL))
		

	SSL_set_fd(ssl, cli_fd);
	if (SSL_accept(ssl) <= 0) {

		err = ERR_get_error();
		pr_err("SSL_accept(\"%s\"): "
		       "[%lu]:[%s]:[%s]:[%s]",
		       key,
		       err,
		       ERR_lib_error_string(err),
		       ERR_func_error_string(err),
		       ERR_reason_error_string(err));

		SSL_shutdown(ssl);
		SSL_free(ssl);

		epoll_delete(thread->epoll_fd, cli_fd);
		thread->epoll_queue_n--;

		mutex_lock(&state->cl_slot_mut);
		reset_client_slot(client, client->slot_idx);
		mutex_unlock(&state->cl_slot_mut);

		ret = false;
		return ret;
	}
	client->ssl = ssl;

	return ret;
}


static void resolve_new_connection(int cli_fd, struct sockaddr_in *saddr,
				   struct srv_tcp_state *state)
{
	char ip_buf[IPV4_L + 1];
	const char *src_ip;
	uint16_t src_port;

	src_ip = resolve_new_client_ip(saddr, ip_buf);
	if (unlikely(src_ip == NULL))
		goto err;

	src_port = ntohs(saddr->sin_port);
	if (likely(plug_to_client_slot(cli_fd, src_ip, src_port, state)))
		return;

	prl_notice(0, "Dropping connection from %s:%u", src_ip, src_port);
err:
	close(cli_fd);
}


static void accept_new_connection(int tcp_fd, struct srv_tcp_state *state)
{

	int err;
	int cli_fd;
	struct sockaddr_in saddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(&saddr, 0, sizeof(struct sockaddr_in));
	cli_fd = accept(tcp_fd, (struct sockaddr *)&saddr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_err("accept(): " PRERF, PREAR(err));
		return;
	}

	resolve_new_connection(cli_fd, &saddr, state);
}


static int handle_tcp_event(int tcp_fd, struct srv_tcp_state *state,
			    uint32_t revents)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -1;

	accept_new_connection(tcp_fd, state);
	return 0;
}


static gt_cli_evt_t handle_client_event2(int cli_fd,
					 struct srv_client_slot *client,
					 struct srv_tcp_thread *thread,
					 struct srv_tcp_state *state)
{
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	ssize_t recv_ret;

	recv_s   = client->recv_s;
	recv_buf = client->recv_buf.raw_buf;
	recv_len = TCLI_PKT_RECV_L - recv_s;

	client->recv_c++;

	recv_ret = recv(cli_fd, recv_buf + recv_s, recv_len, 0);

	return HCE_OK;
}


static int handle_client_event(int cli_fd, uint16_t map_to,
			       struct srv_tcp_thread *thread,
			       struct srv_tcp_state *state, uint32_t revents)
{
	gt_cli_evt_t jump_to;
	struct srv_client_slot *client = &state->clients[map_to];
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (likely(revents & err_mask)) {
		if (err_mask & EPOLLHUP) {
			prl_notice(0, PRWIU " has closed its connection",
				   W_IU(client));
		} else {
			pr_err("Detected error from revents " PRWIU,
			       W_IU(client));
		}
		goto out_close;
	}

	jump_to = handle_client_event2(cli_fd, client, thread, state);
	if (likely(jump_to == HCE_OK)) {
		goto out_ok;
	} else
	if (unlikely(jump_to == HCE_ERR)) {
		goto out_err;
	} else
	if (unlikely(jump_to == HCE_CLOSE)) {
		goto out_close;
	} else {
		__builtin_unreachable();
	}

out_ok:
	return 0;
out_err:
	client->recv_s = 0;
	prl_notice(5, "[%03u] Client " PRWIU " got error", client->err_c,
		   W_IU(client));

	if (unlikely(client->err_c++ >= CLIENT_MAX_ERR)) {
		pr_err("Client " PRWIU " has reached the max number of errors",
		       W_IU(client));
		goto out_close;
	}

	/* Tolerate small error */
	return 0;
out_close:
	prl_notice(0, "Closing connection fd from " PRWIU, W_IU(client));
	epoll_delete(thread->epoll_fd, cli_fd);

	mutex_lock(&state->cl_slot_mut);
	tss_push(&state->cl_stack, client->slot_idx);
	reset_client_slot(client, client->slot_idx);
	mutex_unlock(&state->cl_slot_mut);
	close(cli_fd);

	return 0;
}


static int handle_event(struct srv_tcp_thread *thread,
			struct srv_tcp_state *state, struct epoll_event *event)
{
	int fd;
	int ret = 0;
	uint16_t map_to;
	uint32_t revents;
	uint16_t *epoll_map = state->epoll_map;

	fd      = event->data.fd;
	revents = event->events;
	map_to  = epoll_map[fd];

	switch (map_to) {
	case EPOLL_MAP_TO_NOP:
		pr_err("Error, fd mapped to EPL_MAP_TO_NOP");
		ret = -1;
		break;
	case EPOLL_MAP_TO_TUN:
		ret = handle_tun_event(fd, state, revents);
		break;
	case EPOLL_MAP_TO_TCP:
		ret = handle_tcp_event(fd, state, revents);
		break;
	default:
		map_to -= EPOLL_MAPCL_SHIFT;
		ret = handle_client_event(fd, map_to, thread, state, revents);
		break;
	}

	return ret;
}


static int handle_events(struct srv_tcp_thread *thread,
			 struct srv_tcp_state *state,
			 struct epoll_event *events,
			 int num_of_events)
{
	int ret;

	for (int i = 0; likely(i < num_of_events); i++) {
		ret = handle_event(thread, state, &events[i]);
		if (unlikely(ret < 0))
			return -1;
	}

	return 0;
}



static __no_inline void *event_loop(void *thread_p)
{
	int ret;
	int epoll_fd;
	int epoll_timeout;
	int epoll_max_events;
	struct epoll_event *events = NULL;
	struct srv_tcp_thread *thread = thread_p;
	struct srv_tcp_state *state = thread->state;

	epoll_fd         = thread->epoll_fd;
	epoll_timeout    = thread->epoll_timeout;
	epoll_max_events = thread->epoll_max_events;

	events = calloc_wrp((size_t)epoll_max_events, sizeof(*events));
	if (unlikely(events == NULL))
		goto out;

	thread->events = events;
	memset(events, 0, (size_t)epoll_max_events * sizeof(*events));

	thread->is_active = true;

	while (likely(!state->stop_event_loop)) {
		ret = exec_epoll_wait(epoll_fd, events, epoll_max_events,
				      epoll_timeout);

		if (unlikely(ret == 0))
			continue;

		if (unlikely(ret < 0))
			break;

		if (unlikely(handle_events(thread, state, events, ret) < 0))
			break;
	}

out:
	state->stop_event_loop = true;
	prl_notice(0, "Thread %u is exiting...", thread->thread_num);
	thread->is_active = false;
	return NULL;
}


static int create_epoll_instance(int num)
{
	int err;
	int ret;

	ret = epoll_create(num);
	if (unlikely(ret < 0)) {
		err = errno;
		pr_err("epoll_create(): " PRERF, PREAR(err));
		return -1;
	}

	return ret;
}


static int plug_primary_fds(int epoll_fd, struct srv_tcp_state *state)
{
	int ret;

	ret = epoll_add(epoll_fd, state->tun_fd, EPOLL_INPUT_EVT);
	if (unlikely(ret < 0))
		return -1;

	ret = epoll_add(epoll_fd, state->tcp_fd, EPOLL_INPUT_EVT);
	if (unlikely(ret < 0))
		return -1;

	return ret;
}


static int init_thread_state(uint8_t i, struct srv_tcp_thread *thread,
			     struct srv_tcp_state *state)
{
	int ret;

	ret = create_epoll_instance(state->cfg->sock.max_conn + 3);
	if (unlikely(ret < 0))
		return -1;

	if (unlikely(mutex_init(&thread->epoll_mut) < 0))
		return -1;

	if (i == 0) {
		/* We're initializing main thread, must plug main fds */
		if (unlikely(plug_primary_fds(ret, state) < 0))
			return -1;
	}

	thread->epoll_queue_n    = 0;
	thread->epoll_max_events = 100;
	thread->epoll_timeout    = 500; /* in milliseconds */
	thread->epoll_fd         = ret;
	thread->thread_num       = i;
	thread->is_active        = false;
	thread->events           = NULL;
	thread->state            = state;

	return ret;
}


static int spawn_sub_thread(uint8_t i, struct srv_tcp_thread *thread,
			    struct srv_tcp_state *state)
{
	int err;
	int ret;

	ret = init_thread_state(i, thread, state);
	if (unlikely(ret < 0))
		return -1;

	ret = pthread_create(&thread->thread, NULL, event_loop, thread);
	if (unlikely(ret != 0)) {
		err = (ret > 0) ? ret : -ret;
		pr_err("pthread_create(): " PRERF, PREAR(err));
		return -err;
	}

	ret = pthread_detach(thread->thread);
	if (unlikely(ret != 0)) {
		err = (ret > 0) ? ret : -ret;
		pr_err("pthread_detach(): " PRERF, PREAR(err));
		return -err;
	}

	return ret;
}


static int run_workers(struct srv_tcp_state *state)
{
	struct srv_tcp_thread *threads;
	uint8_t num_of_threads = state->cfg->num_of_threads;

	threads = calloc_wrp(num_of_threads, sizeof(*threads));
	if (unlikely(threads == NULL))
		return -ENOMEM;

	state->threads = threads;
	/*
	 * We don't call pthread_create for threads[0],
	 * because we are going to run the job of threads[0]
	 * on the main thread.
	 */
	for (uint8_t i = 1; i < num_of_threads; i++) {
		if (unlikely(spawn_sub_thread(i, &threads[i], state) != 0))
			return -1;
	}

	if (unlikely(init_thread_state(0, &threads[0], state) < 0))
		return -1;

	prl_notice(0, "Initialization Sequence Completed");
	event_loop(&threads[0]);

	return 0;
}


static void close_file_descriptors(struct srv_tcp_state *state)
{
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct srv_client_slot *clients = state->clients;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(tcp_fd != -1)) {
		prl_notice(0, "Closing state->tcp_fd (%d)", tcp_fd);
		close(tcp_fd);
	}

	while (likely(max_conn--)) {
		struct srv_client_slot *client = &clients[max_conn];
		int cli_fd = client->cli_fd;

		if (likely(cli_fd != -1)) {
			prl_notice(0, "Closing state->clients[%u].cli_fd (%d)",
				   max_conn, cli_fd);
			close(cli_fd);
		}
	}
}


static void clean_up_openssl(struct srv_tcp_state *state)
{
	if (likely(state->ssl_ctx != NULL))
		SSL_CTX_free(state->ssl_ctx);

	if (likely(state->need_ssl_cleanup)) {
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		EVP_cleanup();
		state->need_ssl_cleanup = false;
	}
}


static void wait_for_thread(uint8_t i, struct srv_tcp_thread *thread)
{
	uint16_t counter = 0;

	prl_notice(0, "Waiting for thread %u...", i);
	while (thread->is_active) {
		if (counter++ <= 0xffu) {
			usleep(10000);
			continue;
		}

		/*
		 * Force kill if the sub thread won't exit
		 */
		prl_notice(0, "Cancelling thread %u...", i);
		pthread_cancel(thread->thread);
		sleep(1);
		return;
	}
}


static void wait_for_threads(struct srv_tcp_state *state)
{
	struct srv_tcp_thread *threads = state->threads;
	uint8_t num_of_threads = state->cfg->num_of_threads;

	for (uint8_t i = 1; i < num_of_threads; i++) {

		if (!threads[i].is_active)
			continue;

		wait_for_thread(i, &threads[i]);
	}
}


static void free_threads_resources(struct srv_tcp_state *state)
{
	struct srv_tcp_thread *threads = state->threads;
	uint8_t num_of_threads = state->cfg->num_of_threads;

	for (uint8_t i = 0; i < num_of_threads; i++) {
		int epoll_fd = threads[i].epoll_fd;

		if (likely(epoll_fd != -1)) {
			prl_notice(0, "Closing state->threads[%u].epoll_fd "
				   "(%u)", i, epoll_fd);
			close(epoll_fd);
		}

		mutex_destroy(&threads[i].epoll_mut);
		free(threads[i].events);
	}
	sleep(1);
}


static void destroy_state(struct srv_tcp_state *state)
{
	state->stop_event_loop = true;
	if (state->intr_sig != -1) {
		int sig = state->intr_sig;
		pr_notice("Signal %d (%s) has been caught", sig,
			  strsignal(sig));
	}

	wait_for_threads(state);
	free_threads_resources(state);

	close_file_descriptors(state);
	clean_up_openssl(state);

	mutex_destroy(&state->cl_slot_mut);
	tss_destroy(&state->cl_stack);

	free(state->threads);
	free(state->clients);
	free(state->epoll_map);
	free(state->ip_map);
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int ret;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, handle_interrupt);
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGQUIT, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	ret = init_state(&state);
	if (unlikely(ret < 0))
		goto out;
	ret = init_iface(&state);
	if (unlikely(ret < 0))
		goto out;
	ret = init_openssl(&state);
	if (unlikely(ret < 0))
		goto out;
	ret = init_ssl_context(&state);
	if (unlikely(ret < 0))
		goto out;
	ret = init_socket(&state);
	if (unlikely(ret < 0))
		goto out;
	ret = run_workers(&state);
out:
	destroy_state(&state);
	return ret;
}

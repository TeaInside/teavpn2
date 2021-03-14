
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <stdalign.h>
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

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wunused-macros"
#endif

#define MAX_ERR_C	(0xfu)

#define EPL_MAP_SIZE	(0xffffu)
#define EPL_MAP_TO_NOP	(0x0u)
#define EPL_MAP_TO_TUN	(0x1u)
#define EPL_MAP_TO_TCP	(0x2u)
/* EPL_MAP_SHIFT must be the number of EPL_MAP_TO_* constants */
#define EPL_MAP_SHIFT	(0x3u)

#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)
#define IP_MAP_TO_NOP	(0x0u)
#define IP_MAP_SHIFT	(0x1u)

/* Macros for printing  */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


typedef enum _gt_cli_evt_t {
	HCE_OK = 0,
	HCE_ERR = 1,
	HCE_CLOSE = 2
} gt_cli_evt_t;


struct client_slot {
	int			cli_fd;
	uint32_t		recv_c;
	uint32_t		send_c;
	int32_t			bc_arr_idx;
	uint16_t		client_idx;
	char			uname[64];

	bool			is_auth;
	bool			is_used;
	bool			is_conn;
	uint8_t			err_c;

	char			src_ip[IPV4_L];
	uint16_t		src_port;
	uint32_t		ipv4; /* Private IP */

	/* Number of unprocessed bytes in recv_buf */
	struct_pad(1, 4);
	size_t			recv_s;
	utcli_pkt_t		recv_buf;
};


/* Stack to retrieve client slot in O(1) time complexity */
struct cl_slot_stk {
	uint16_t		sp;	/* Stack pointer       */
	uint16_t		max_sp;	/* Max stack pointer   */
	struct_pad(0, 4);
	uint16_t		*arr;	/* The array container */
};


/* Must read that header file */
#include <teavpn2/server/bc_arr.h>


struct srv_tcp_state {
	int			epoll_fd;
	int			tcp_fd;
	int			tun_fd;

	bool			stop;
	struct_pad(0, 3);

	struct cl_slot_stk	client_stack;
	struct srv_cfg		*cfg;
	struct client_slot	*clients;
	uint16_t		*epoll_map;

	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`
	 */
	uint16_t		(*ip_map)[256];

	/* Counters */
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	struct bc_arr		bc_arr_ct;
	utsrv_pkt_t		send_buf;
	struct iface_cfg	siff;
	bool			need_iface_down;
	bool			aff_ok;
	struct_pad(1, 4);
	cpu_set_t		aff;
};

static struct srv_tcp_state *g_state;


static void handle_interrupt(int sig)
{
	struct srv_tcp_state *state = g_state;
	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int32_t push_client_stack(struct cl_slot_stk *client_stack, uint16_t val)
{
	uint16_t sp = client_stack->sp;

	TASSERT(sp > 0);
	client_stack->arr[--sp] = val;
	client_stack->sp = sp;
	return (int32_t)val;
}


static int32_t pop_client_stack(struct cl_slot_stk *client_stack)
{
	int32_t val;
	uint16_t sp = client_stack->sp;
	uint16_t max_sp = client_stack->max_sp;

	/* sp must never be higher than max_sp */
	TASSERT(sp <= max_sp);

	if (unlikely(sp == max_sp)) {
		/* There is nothing on the stack */
		return -1;
	}

	val = (int32_t)client_stack->arr[sp];
	client_stack->sp = ++sp;
	return val;
}


static void *calloc_wrp(size_t nmemb, size_t size)
{
	int err;
	void *mem;

	mem = calloc(nmemb, size);
	if (unlikely(mem == NULL)) {
		err = errno;
		pr_err("calloc: Cannot allocate memory " PRERF, PREAR(err));
		return NULL;
	}

	return mem;
}


static int init_state_client_stack(struct srv_tcp_state *state)
{
	uint16_t *arr;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct cl_slot_stk *clstk = &state->client_stack;

	arr = calloc_wrp(EPL_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(arr == NULL))
		return -1;

	clstk->sp     = max_conn; /* Stack growsdown, so sp starts at high */
	clstk->max_sp = max_conn;
	clstk->arr    = arr;

	while (max_conn--)
		push_client_stack(clstk, max_conn);

	return 0;
}


/*
 * Caller is responsible to keep track the index (client_idx).
 */
static void reset_client_slot(struct client_slot *client, uint16_t client_idx)
{
	client->cli_fd      = -1;

	client->recv_c      = 0;
	client->send_c      = 0;

	client->client_idx  = client_idx;

	client->uname[0]    = '_';
	client->uname[1]    = '\0';

	client->is_used     = false;
	client->is_auth     = false;
	client->is_conn     = false;
	client->bc_arr_idx  = -1;
	client->err_c       = 0;
	client->recv_s      = 0;

	client->ipv4        = 0;
}


static int init_state_client_slots(struct srv_tcp_state *state)
{
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct client_slot *clients;

	clients = calloc_wrp(max_conn, sizeof(struct client_slot));
	if (unlikely(clients == NULL))
		return -1;

	while (likely(max_conn--))
		reset_client_slot(clients + max_conn, max_conn);

	state->clients = clients;
	return 0;
}


static int init_state_epoll_map(struct srv_tcp_state *state)
{
	uint16_t *epoll_map;

	epoll_map = calloc_wrp(EPL_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(epoll_map == NULL))
		return -1;

	for (uint16_t fd = 0; fd < EPL_MAP_SIZE; fd++)
		epoll_map[fd] = EPL_MAP_TO_NOP;

	state->epoll_map = epoll_map;
	return 0;
}


static int init_state_ip_map(struct srv_tcp_state *state)
{
	uint16_t (*ip_map)[256];

	ip_map = calloc_wrp(256, sizeof(uint16_t [256]));
	if (unlikely(ip_map == NULL))
		return -1;

	for (uint16_t i = 0; i < 256; i++) {
		for (uint16_t j = 0; j < 256; j++) {
			ip_map[i][j] = IP_MAP_TO_NOP;
		}
	}

	state->ip_map = ip_map;
	return 0;
}


static int init_state(struct srv_tcp_state *state)
{
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct cpu_ret_info cri;

	if (optimize_cpu_affinity(1, &cri) == 0) {
		memcpy(&state->aff, &cri.affinity, sizeof(state->aff));
		state->aff_ok = true;
	} else {
		state->aff_ok = false;
	}

	optimize_process_priority(-20, &cri);

	if (unlikely(init_state_client_stack(state) < 0))
		return -1;
	if (unlikely(init_state_client_slots(state) < 0))
		return -1;
	if (unlikely(init_state_epoll_map(state) < 0))
		return -1;
	if (unlikely(init_state_ip_map(state) < 0))
		return -1;
	if (unlikely(bc_arr_init(&state->bc_arr_ct, max_conn) < 0))
		return -1;

	state->epoll_fd     = -1;
	state->tcp_fd       = -1;
	state->tun_fd       = -1;
	state->stop         = false;
	state->read_tun_c   = 0;
	state->write_tun_c  = 0;
	state->need_iface_down = false;

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

	state->tun_fd = tun_fd;
	state->need_iface_down = true;
	return 0;
out_err:
	close(tun_fd);
	return -1;
}


static int socket_setup(int fd, struct srv_tcp_state *state)
{
	int rv;
	int err;
	int y;
	bool soi = false;
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *pv = (const void *)&y;
	const char *lv, *on;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}

	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &state->aff)) {
			y = i;
			soi = true;
			break;
		}
	}

	if (soi) {
		prl_notice(4, "Pinning SO_INCOMING_CPU to CPU %d", y);
		rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
		if (unlikely(rv < 0)) {
			lv = "SOL_SOCKET";
			on = "SO_INCOMING_CPU";
			rv = 0;
			goto out_err;
		}
	}

	y = 1024 * 1024 * 4;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	rv = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}

	y = 30000;
	rv = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}

	/*
	 * TODO: Utilize `cfg` to set some socket options from config
	 */
	(void)cfg;
	return rv;
out_err:
	err = errno;
	pr_err("setsockopt(%s, %s): " PRERF, lv, on, PREAR(err));
	return rv;
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
		retval = -err;
		pr_err("socket(): " PRERF, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Setting up socket file descriptor...");
	retval = socket_setup(tcp_fd, state);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);

	retval = bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("bind(): " PRERF, PREAR(err));
		goto out_err;
	}

	retval = listen(tcp_fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("listen(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = tcp_fd;
	prl_notice(0, "Listening on %s:%u...", sock->bind_addr,
		   sock->bind_port);

	return retval;
out_err:
	if (tcp_fd > 0)
		close(tcp_fd);
	return retval;
}


static int epoll_add(int epl_fd, int fd, uint32_t events)
{
	int err;
	struct epoll_event event;

	/* Shut the valgrind up! */
	memset(&event, 0, sizeof(struct epoll_event));

	event.events = events;
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


static int init_epoll(struct srv_tcp_state *state)
{
	int err;
	int ret;
	int epl_fd = -1;
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create((int)state->cfg->sock.max_conn + 3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	state->epoll_map[tun_fd] = EPL_MAP_TO_TUN;
	ret = epoll_add(epl_fd, tun_fd, EPL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epoll_map[tcp_fd] = EPL_MAP_TO_TCP;
	ret = epoll_add(epl_fd, tcp_fd, EPL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epoll_fd = epl_fd;
	return 0;

out_create_err:
	err = errno;
	pr_err("epoll_create(): " PRERF, PREAR(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return -1;
}


static int exec_epoll_wait(int epoll_fd, struct epoll_event *events,
			   int maxevents)
{
	int err;
	int retval;

	retval = epoll_wait(epoll_fd, events, maxevents, 3000);
	if (unlikely(retval == 0)) {
		/*
		 * epoll_wait() reaches timeout
		 *
		 * TODO: Do something meaningful here.
		 */
		return 0;
	}

	if (unlikely(retval < 0)) {
		err = errno;
		if (err == EINTR) {
			retval = 0;
			prl_notice(0, "Interrupted!");
			return 0;
		}

		pr_err("epoll_wait(): " PRERF, PREAR(err));
		return -err;
	}

	return retval;
}



static size_t set_srv_pkt_buf(tsrv_pkt_t *srv_pkt, tsrv_pkt_type_t type,
			      uint16_t length)
{
	srv_pkt->type   = type;
	srv_pkt->npad   = 0;
	srv_pkt->length = htons(length);

	return TSRV_PKT_MIN_L + length;
}


static ssize_t send_to_client(struct client_slot *client,
			      const tsrv_pkt_t *srv_pkt,
			      size_t len)
{
	int err;
	ssize_t send_ret;
	int cli_fd = client->cli_fd;

	client->send_c++;

	send_ret = send(cli_fd, srv_pkt, len, 0);
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/*
			 * TODO: Handle pending buffer
			 *
			 * For now, let it fallthrough to error.
			 */
		}

		pr_err("send(fd=%d) " PRERF, cli_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %ld bytes to " PRWIU,
		   client->send_c, cli_fd, send_ret, W_IU(client));

	return send_ret;
}


static void route_ipv4(struct srv_tcp_state *state, tsrv_pkt_t *srv_pkt,
		       size_t len)
{
	uint32_t dst;
	uint16_t i;
	uint16_t j;
	uint16_t map_to;
	size_t send_len;
	struct client_slot *client;
	uint16_t (*ip_map)[256] = state->ip_map;
	struct iphdr *header = &srv_pkt->net_pkt.header;

	dst = header->daddr;
	i = dst & 0xffu;
	j = (dst >> 8u) & 0xffu;

	map_to = ip_map[i][j];
	if (unlikely(map_to == IP_MAP_TO_NOP))
		return;

	map_to  -= IP_MAP_SHIFT;
	client   = &state->clients[map_to];
	send_len = set_srv_pkt_buf(srv_pkt, TSRV_PKT_IFACE_DATA, (uint16_t)len);
	send_to_client(client, srv_pkt, send_len);
}


static void broadcast_packet(struct srv_tcp_state *state, tsrv_pkt_t *srv_pkt,
			     size_t len)
{
	size_t send_len;
	struct client_slot *client;
	struct bc_arr *bc_arr_ct = &state->bc_arr_ct;

	send_len = set_srv_pkt_buf(srv_pkt, TSRV_PKT_IFACE_DATA, (uint16_t)len);

	BC_ARR_FOREACH(bc_arr_ct) {
		client = &state->clients[__data];
		send_to_client(client, srv_pkt, send_len);
	}
}


static void route_packet(struct srv_tcp_state *state, tsrv_pkt_t *srv_pkt,
			 size_t len)
{
	struct iphdr *header = &srv_pkt->net_pkt.header;

	if (header->version == 4){
		route_ipv4(state, srv_pkt, len);
	} else {
		/* TODO: Add IPv6 support */

		/* We don't yet know where to send, so just broadcast it. */
		broadcast_packet(state, srv_pkt, len);
	}
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

	route_packet(state, srv_pkt, (size_t)read_ret);
	return read_ret;
}


static int handle_tun_event(int tun_fd, struct srv_tcp_state *state,
			    uint32_t revents)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -1;

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


static bool plug_to_client_slot(int cli_fd, const char *src_ip,
				uint16_t src_port,
				struct srv_tcp_state *state)
{
	int err;
	uint16_t idx;
	int32_t ret_idx;
	struct client_slot *client;

	ret_idx = pop_client_stack(&state->client_stack);
	if (unlikely(ret_idx == -1)) {
		prl_notice(0, "Client slot is full, can't accept connection");
		return false;
	}

	idx = (uint16_t)ret_idx;
	err = epoll_add(state->epoll_fd, cli_fd, EPL_IN_EVT);
	if (unlikely(err < 0)) {
		pr_err("Cannot accept new connection from %s:%u because of "
		       "error on epoll_add()", src_ip, src_port);
		return false;
	}

	/*
	 * state->epl_map[cli_fd] must not be in use
	 */
	TASSERT(state->epoll_map[cli_fd] == EPL_MAP_TO_NOP);

	/*
	 * Map the FD to translate to idx later
	 */
	state->epoll_map[cli_fd] = idx + EPL_MAP_SHIFT;

	client = &state->clients[idx];
	client->is_used  = true;
	client->is_conn  = true;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;

	sane_strncpy(client->src_ip, src_ip, IPV4_L);

	prl_notice(0, "New connection from " PRWIU " (fd:%d)", W_IU(client),
		   cli_fd);

	return true;
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
	cli_fd = accept(tcp_fd, (void *)&saddr, &addrlen);
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


static void panic_dump(void *ptr, size_t len)
{
	if ((NOTICE_MAX_LEVEL) >= 5) {
		panic("Data corrution detected!");
		VT_HEXDUMP(ptr, len);
		panic("Not syncing --");
	}
}


static void print_corruption_notice(struct client_slot *client)
{
	tcli_pkt_t *cli_pkt = client->recv_buf.__pkt_chk;
	panic_dump(cli_pkt, sizeof(*cli_pkt));
}


/* _b_ means return bool */
static bool send_b_welcome(struct client_slot *client,
			   struct srv_tcp_state *state)
{
	size_t send_len;
	tsrv_pkt_t *srv_pkt = state->send_buf.__pkt_chk;

	send_len = set_srv_pkt_buf(srv_pkt, TSRV_PKT_WELCOME, 0);
	return send_to_client(client, srv_pkt, send_len) > 0;
}


/* _b_ means return bool */
static bool send_b_auth_reject(struct client_slot *client,
			       struct srv_tcp_state *state)
{
	size_t send_len;
	tsrv_pkt_t *srv_pkt = state->send_buf.__pkt_chk;

	send_len = set_srv_pkt_buf(srv_pkt, TSRV_PKT_AUTH_REJECT, 0);
	return send_to_client(client, srv_pkt, send_len) > 0;
}


/* _b_ means return bool */
static bool send_b_auth_ok(struct client_slot *client,
			   struct srv_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	tsrv_pkt_t *srv_pkt = state->send_buf.__pkt_chk;

	data_len = sizeof(struct tsrv_aok_pkt);
	send_len = set_srv_pkt_buf(srv_pkt, TSRV_PKT_AUTH_OK, data_len);
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static gt_cli_evt_t handle_clpkt_hello(tcli_pkt_t *cli_pkt,
				       struct client_slot *client,
				       uint16_t data_len,
				       struct srv_tcp_state *state)
{
	version_t cmp_ver = {
		.ver       = VERSION,
		.patch_lvl = PATCHLEVEL,
		.sub_lvl   = SUBLEVEL,
		.extra     = EXTRAVERSION
	};
	struct tcli_hello_pkt *hlo_pkt;

	/* Ignore hello packet from authenticated client */
	if (unlikely(client->is_auth))
		return HCE_OK;

	/* Wrong data length */
	if (unlikely(data_len != sizeof(cmp_ver))) {
		prl_notice(0, "Client " PRWIU " sends invalid hello data "
			   "length (expected: %zu; got: %u)", W_IU(client),
			   sizeof(cmp_ver), data_len);
		return HCE_CLOSE;
	}

	hlo_pkt = &cli_pkt->hello_pkt;

	if (unlikely(memcmp(&hlo_pkt->v, &cmp_ver, sizeof(cmp_ver)) != 0)) {

		/*
		 * For safe print, in case client sends non null-terminated
		 */
		hlo_pkt->v.extra[sizeof(hlo_pkt->v.extra) - 1] = '\0';

		pr_err("Invalid client version from " PRWIU
		       " (got: %u.%u.%u%s; expected: %u.%u.%u%s)",
		       W_IU(client),
		       hlo_pkt->v.ver,
		       hlo_pkt->v.patch_lvl,
		       hlo_pkt->v.sub_lvl,
		       hlo_pkt->v.extra,
		       cmp_ver.ver,
		       cmp_ver.patch_lvl,
		       cmp_ver.sub_lvl,
		       cmp_ver.extra);

		return HCE_CLOSE;
	}

	return send_b_welcome(client, state) ? HCE_OK : HCE_CLOSE;
}


static gt_cli_evt_t handle_clpkt_auth(tcli_pkt_t *cli_pkt,
				      struct client_slot *client,
				      uint16_t data_len,
				      struct srv_tcp_state *state)
{
	bool is_auth_succeed;
	struct srv_cfg *cfg = state->cfg;
	tsrv_pkt_t *srv_pkt = state->send_buf.__pkt_chk;
	struct auth_ret	*aret = &srv_pkt->auth_ok.aret;
	struct iface_cfg *iff = &aret->iface;
	struct tcli_auth_pkt *auth_pkt = &cli_pkt->auth_pkt;
	char *uname = auth_pkt->uname;
	char *pass  = auth_pkt->pass;
	uint32_t ipv4;

	if (unlikely(client->is_auth))
		return HCE_OK;

	if (unlikely(data_len != sizeof(struct tcli_auth_pkt))) {
		prl_notice(0, "Client " PRWIU " sends invalid auth packet "
			      "length (expected: %zu; got: %u)", W_IU(client),
			      sizeof(struct tcli_auth_pkt),
			      data_len);
		return HCE_CLOSE;
	}

	sane_strncpy(client->uname, uname, sizeof(client->uname));

	memset(iff, 0, sizeof(struct iface_cfg));
	is_auth_succeed = teavpn_server_auth(cfg, aret, uname, pass);
	memzero_explicit(&auth_pkt->pass, sizeof(auth_pkt->pass));

	if (unlikely(!is_auth_succeed)) {
		prl_notice(0, "Authentication failed from " PRWIU,
			   W_IU(client));
		goto out_auth_failed;
	}

	sane_strncpy(iff->ipv4_dgateway, cfg->iface.ipv4,
		     sizeof(iff->ipv4_dgateway));
	sane_strncpy(iff->ipv4_pub, cfg->sock.exposed_addr,
		     sizeof(iff->ipv4_pub));
	iff->mtu = htons(iff->mtu);

	errno = 0;
	ipv4 = 0;
	if (unlikely(!inet_pton(AF_INET, iff->ipv4, &ipv4))) {
		int err = errno;
		err = err ? err : EINVAL;
		pr_err("inet_pton(%s) for " PRWIU ": " PRERF, iff->ipv4,
		       W_IU(client), PREAR(err));
		goto out_auth_failed;
	}

	client->ipv4 = ipv4;

	/* TODO: Set IP Map, set index, etc. */

	if (unlikely(!send_b_auth_ok(client, state))) {
		prl_notice(0, "Authentication error from " PRWIU, W_IU(client));
		goto out_auth_failed;
	}

	prl_notice(0, "Authentication success from " PRWIU, W_IU(client));
	prl_notice(0, "Assigning IP %s to " PRWIU, iff->ipv4, W_IU(client));

	client->is_auth = true;
	return HCE_OK;

out_auth_failed:
	send_b_auth_reject(client, state);
	return HCE_CLOSE;
}


static gt_cli_evt_t handle_clpkt_iface_ack(struct client_slot *client,
					   struct srv_tcp_state *state)
{
	char priv_ip[IPV4_L];
	uint32_t ipv4 = client->ipv4;
	uint16_t i;
	uint16_t j;
	int32_t k;

	if (unlikely(!client->is_auth)) {
		prl_notice(0, "Unauthenticated client trying to send iface "
			      "ack " PRWIU, W_IU(client));
		return HCE_CLOSE;
	}

	i = ipv4 & 0xffu;
	j = (ipv4 >> 8u) & 0xffu;
	state->ip_map[i][j] = client->client_idx + IP_MAP_SHIFT;

	inet_ntop(AF_INET, &client->ipv4, priv_ip, sizeof(priv_ip));
	prl_notice(0, PRWIU " acknowledged the IP assignment (%s)",
		   W_IU(client), priv_ip);

	k = bc_arr_insert(&state->bc_arr_ct, client->client_idx);
	if (unlikely(k == -1)) {
		state->stop = true;
		pr_err("Bug bc_arr_insert");
		return HCE_CLOSE;
	}
	client->bc_arr_idx = k;

	return HCE_OK;
}


static ssize_t handle_iface_write(tcli_pkt_t *cli_pkt,
				  struct client_slot *client,
				  uint16_t data_len,
				  struct srv_tcp_state *state)
{
	ssize_t write_ret;
	int tun_fd = state->tun_fd;

	state->write_tun_c++;

	write_ret = write(tun_fd, cli_pkt->raw_data, data_len);
	if (unlikely(write_ret < 0)) {
		int err = errno;
		if (err == EAGAIN) {
			/* TODO: Handle pending TUN/TAP buffer */
			pr_err("Pending buffer detected on write(): EAGAIN "
			       PRWIU, W_IU(client));
			return 0;
		}

		pr_err("write(fd=%d) to tun_fd" PRERF " " PRWIU, tun_fd,
		       PREAR(err), W_IU(client));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] write(fd=%d) %zd bytes to tun_fd " PRWIU,
		   state->write_tun_c, tun_fd, write_ret, W_IU(client));

	return write_ret;
}


static gt_cli_evt_t handle_clpkt_iface_data(tcli_pkt_t *cli_pkt,
					    struct client_slot *client,
					    uint16_t data_len,
					    struct srv_tcp_state *state)
{
	ssize_t write_ret;

	if (unlikely(!client->is_auth)) {
		prl_notice(0, "Unauthenticated client trying to send iface "
			      "data " PRWIU, W_IU(client));
		return HCE_CLOSE;
	}

	write_ret = handle_iface_write(cli_pkt, client, data_len, state);

	/* TODO: Broadcast the packet to other clients */

	return (write_ret > 0) ? HCE_OK : HCE_ERR;
}


static gt_cli_evt_t process_client_pkt(tcli_pkt_t *cli_pkt,
				       struct client_slot *client,
				       uint16_t data_len,
				       struct srv_tcp_state *state)
{
	tcli_pkt_type_t pkt_type = cli_pkt->type;
	
	if (likely(pkt_type == TCLI_PKT_IFACE_DATA))
		return handle_clpkt_iface_data(cli_pkt, client, data_len,
					       state);
	if (unlikely(pkt_type == TCLI_PKT_HELLO))
		return handle_clpkt_hello(cli_pkt, client, data_len, state);
	if (unlikely(pkt_type == TCLI_PKT_AUTH))
		return handle_clpkt_auth(cli_pkt, client, data_len, state);
	if (unlikely(pkt_type == TCLI_PKT_IFACE_ACK))
		return handle_clpkt_iface_ack(client, state);
	if (unlikely(pkt_type == TCLI_PKT_REQSYNC))
		return HCE_OK;
	if (unlikely(pkt_type == TCLI_PKT_PING))
		return HCE_OK;
	if (unlikely(pkt_type == TCLI_PKT_CLOSE))
		return HCE_CLOSE;

	print_corruption_notice(client);

	prl_notice(0, "Client " PRWIU " sends invalid packet type (type: %d) "
		      "CORRUPTED PACKET?", W_IU(client), pkt_type);

	return client->is_auth ? HCE_ERR : HCE_CLOSE;
}


static gt_cli_evt_t handle_client_event3(size_t recv_s,
					 struct client_slot *client,
					 struct srv_tcp_state *state)
{
	char *recv_buf;
	tcli_pkt_t *cli_pkt;

	uint8_t  npad;
	uint16_t data_len;
	size_t   fdata_len; /* Expected full data length + plus pad    */
	size_t   cdata_len; /* Current received data length + plus pad */
	gt_cli_evt_t retval;

	recv_buf = client->recv_buf.raw_buf;
	cli_pkt  = client->recv_buf.__pkt_chk;

process_again:
	if (unlikely(recv_s < TCLI_PKT_MIN_L)) {
		/*
		 * At this point, the packet has not been fully received.
		 *
		 * We have to wait for more bytes to identify the type of
		 * packet and its length.
		 *
		 * Bail out!
		 */
		goto out;
	}

	npad      = cli_pkt->npad;
	data_len  = ntohs(cli_pkt->length);
	fdata_len = data_len + npad;
	if (unlikely(data_len > TCLI_PKT_MAX_L)) {

		print_corruption_notice(client);

		/*
		 * `data_len` must **never be greater** than TCLI_PKT_MAX_L.
		 *
		 * If we reach this block, then it must be corrupted packet!
		 *
		 * BTW, there are several possibilities here:
		 * - Client has been compromised to intentionally send broken
		 *   packet (it's very unlikely, uh...).
		 * - Packet has been corrupted when it was on the way (maybe
		 *   ISP problem?).
		 * - Bug on something we haven't yet known.
		 */
		prl_notice(0, "Client " PRWIU " sends invalid packet length "
			      "(max_allowed_len = %zu; cli_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", W_IU(client),
			      TCLI_PKT_MAX_L, data_len, recv_s);

		return client->is_auth ? HCE_ERR : HCE_CLOSE;
	}

	/* Calculate current received data length */
	cdata_len = recv_s - TCLI_PKT_MIN_L;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * Data has not been fully received. Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}

	assert(cdata_len >= fdata_len);
	retval = process_client_pkt(cli_pkt, client, data_len, state);
	if (unlikely(retval != HCE_OK))
		return retval;

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra bytes on the tail, must memmove to the front
		 * before we run out of buffer.
		 */

		char *source_ptr;
		size_t processed_len;
		size_t unprocessed_len;

		processed_len   = TCLI_PKT_MIN_L + fdata_len;
		unprocessed_len = recv_s - processed_len;
		source_ptr      = &(recv_buf[processed_len]);
		recv_s          = unprocessed_len;
		memmove(recv_buf, source_ptr, unprocessed_len);

		prl_notice(5, "memmove " PRWIU " (copy_size: %zu; "
			      "processed_len: %zu)",
			      W_IU(client), recv_s, processed_len);

		goto process_again;
	}

	recv_s = 0;
out:
	client->recv_s = recv_s;
	return HCE_OK;
}


static gt_cli_evt_t handle_client_event2(int cli_fd,
					 struct client_slot *client,
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
	if (unlikely(recv_ret < 0)) {
		int err = errno;
		if (err == EAGAIN)
			return HCE_OK;

		pr_err("recv(fd=%d): " PRERF " " PRWIU, cli_fd, PREAR(err),
		       W_IU(client));

		return HCE_ERR;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, PRWIU " has closed its connection", W_IU(client));
		return HCE_CLOSE;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "[%10" PRIu32 "] recv(fd=%d) %zd bytes from " PRWIU
		   " (recv_s = %zu)", client->recv_c, cli_fd, recv_ret,
		   W_IU(client), recv_s);

	return handle_client_event3(recv_s, client, state);
}


static int handle_client_event(int cli_fd, uint16_t map_to,
			       struct srv_tcp_state *state, uint32_t revents)
{
	gt_cli_evt_t jump_to;
	struct client_slot *client = &state->clients[map_to];
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask)) {

		if (err_mask & EPOLLHUP) {
			prl_notice(0, PRWIU " has closed its connection",
				   W_IU(client));
		} else {
			pr_err("Detected error from revents " PRWIU,
			       W_IU(client));
		}

		goto out_close;
	}

	jump_to = handle_client_event2(cli_fd, client, state);
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

	if (unlikely(client->err_c++ >= MAX_ERR_C)) {
		pr_err("Client " PRWIU " has reached the max number of errors",
		       W_IU(client));
		goto out_close;
	}

	/* Tolerate small error */
	return 0;

out_close:
	epoll_delete(state->epoll_fd, cli_fd);
	close(cli_fd);

	if (likely(client->ipv4 != 0)) {
		uint32_t ipv4 = client->ipv4;
		uint16_t i = ipv4 & 0xffu;
		uint16_t j = (ipv4 >> 8) & 0xffu;
		prl_notice(0, "Reset state->ip_map[%u][%u]", i, j);
		state->ip_map[i][j] = IP_MAP_TO_NOP;
	}

	if (likely(client->bc_arr_idx != -1)) {
		bool ret;
		ret = bc_arr_remove(&state->bc_arr_ct,
				    (uint16_t)client->bc_arr_idx);
		if (unlikely(!ret)) {
			state->stop = true;
			pr_err("Bug detected on bc_arr_remove");
		}
	}

	prl_notice(0, "Closing connection fd from " PRWIU, W_IU(client));

	/* Restore the slot into the stack */
	push_client_stack(&state->client_stack, client->client_idx);

	/* Reset client state */
	reset_client_slot(client, client->client_idx);

	state->epoll_map[cli_fd] = EPL_MAP_TO_NOP;
	return 0;
}


static int handle_event(struct srv_tcp_state *state, struct epoll_event *event)
{
	int fd;
	int retval = 0;
	uint16_t map_to;
	uint32_t revents;
	uint16_t *epoll_map = state->epoll_map;

	fd      = event->data.fd;
	revents = event->events;
	map_to  = epoll_map[fd];

	switch (map_to) {
	case EPL_MAP_TO_NOP:
		pr_err("Error, fd mapped to EPL_MAP_TO_NOP");
		retval = -1;
		break;
	case EPL_MAP_TO_TUN:
		retval = handle_tun_event(fd, state, revents);
		break;
	case EPL_MAP_TO_TCP:
		retval = handle_tcp_event(fd, state, revents);
		break;
	default:
		map_to -= EPL_MAP_SHIFT;
		retval = handle_client_event(fd, map_to, state, revents);
		break;
	}

	return retval;
}


static int handle_events(struct srv_tcp_state *state,
			 struct epoll_event *events,
			 int num_of_events)
{
	int retval;

	for (int i = 0; likely(i < num_of_events); i++) {
		retval = handle_event(state, &events[i]);
		if (unlikely(retval < 0))
			return -1;
	}

	return 0;
}


static int event_loop(struct srv_tcp_state *state)
{
	int retval = 0;
	int maxevents = 16;
	int epoll_fd = state->epoll_fd;
	struct epoll_event events[16];

	/* Shut the valgrind up! */
	memset(events, 0, sizeof(events));

	while (likely(!state->stop)) {
		retval = exec_epoll_wait(epoll_fd, events, maxevents);

		if (unlikely(retval == 0))
			continue;

		if (unlikely(retval < 0))
			goto out;

		retval = handle_events(state, events, retval);
		if (unlikely(retval < 0))
			goto out;
	}

out:
	return retval;
}


static void close_client_slots(struct srv_tcp_state *state)
{
	struct client_slot *clients = state->clients;
	uint16_t max_conn = state->cfg->sock.max_conn;

	while (max_conn--) {
		struct client_slot *client = clients + max_conn;

		if (likely(client->is_used)) {
			prl_notice(0, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);
		}
	}
}


static void close_file_descriptors(struct srv_tcp_state *state)
{
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;
	int epoll_fd = state->epoll_fd;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(tcp_fd != -1)) {
		prl_notice(0, "Closing state->tcp_fd (%d)", tcp_fd);
		close(tcp_fd);
	}

	if (likely(epoll_fd != -1)) {
		prl_notice(0, "Closing state->epoll_fd (%d)", epoll_fd);
		close(epoll_fd);
	}

	close_client_slots(state);
}


static void free_state(struct srv_tcp_state *state)
{
	free(state->client_stack.arr);
	free(state->clients);
	free(state->epoll_map);
	free(state->ip_map);
	free(state->bc_arr_ct.arr);
	memset(state, 0, sizeof(struct srv_tcp_state));
}


static void destroy_state(struct srv_tcp_state *state)
{
	if (state->need_iface_down) {
		prl_notice(0, "Cleaning network interface...");
		teavpn_iface_down(&state->siff);
	}

	close_file_descriptors(state);
	free_state(state);
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, handle_interrupt);
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGQUIT, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_epoll(&state);
	if (unlikely(retval < 0))
		goto out;
	prl_notice(0, "Initialization Sequence Completed");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

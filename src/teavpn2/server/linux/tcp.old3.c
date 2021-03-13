
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
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
/*
 * EPL_MAP_ADD must be the number of EPL_MAP_TO_* constants
 */
#define EPL_MAP_ADD	(0x3u)

#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)
#define IP_MAP_TO_NOP	(0x0u)
#define IP_MAP_ADD	(0x1u)

/*
 * Macros for printing 
 */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


struct client_slot {
	int			cli_fd;

	uint32_t		recv_c;
	uint32_t		send_c;

	uint16_t		client_idx;
	char			uname[64];

	bool			is_auth;
	bool			is_used;
	bool			is_conn;

	uint8_t			err_c;
	char			src_ip[IPV4_L];
	uint16_t		src_port;
	struct_pad(0, 4);

	/* Number of unprocessed bytes in recv_buf */
	size_t			recv_s;

	utcli_pkt_t		recv_buf;
};


/*
 * Stack to retrieve client slot in O(1) time complexity
 */
struct cl_slot_stk {
	uint16_t		sp;	/* Stack pointer       */
	uint16_t		max_sp;	/* Max stack pointer   */
	struct_pad(0, 4);
	uint16_t		*arr;	/* The array container */
};


/*
 * Broadcast array.
 *
 * Whenever there is a packet that should be broadcasted
 * to all clients, we use this struct to enumerate the
 * client index slot.
 */
struct _bc_arr {
	uint16_t		n;
	struct_pad(0, 6);
	uint16_t		*arr;
};


struct srv_tcp_state {
	int			epoll_fd;
	int			tcp_fd;
	int			tun_fd;
	struct_pad(0, 4);
	struct cl_slot_stk	client_stack;
	struct client_slot	*clients;
	uint16_t		*epoll_map;

	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`
	 */
	uint16_t		(*ip_map)[256];

	struct srv_cfg		*cfg;

	/* Counters */
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	struct _bc_arr		bc_idx_arr;

	utsrv_pkt_t		send_buf;
	bool			stop;
	struct_pad(1, 7);
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

	client->err_c       = 0;
	client->recv_s      = 0;
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


static int init_state_broadcast_arr(struct srv_tcp_state *state)
{
	uint16_t *bc_arr;

	bc_arr = calloc_wrp(state->cfg->sock.max_conn, sizeof(uint16_t));
	if (unlikely(bc_arr == NULL))
		return -1;

	state->bc_idx_arr.n = 0;
	state->bc_idx_arr.arr = bc_arr;
	return 0;
}


static int init_state(struct srv_tcp_state *state)
{

	if (unlikely(init_state_client_stack(state) < 0))
		return -1;
	if (unlikely(init_state_client_slots(state) < 0))
		return -1;
	if (unlikely(init_state_epoll_map(state) < 0))
		return -1;
	if (unlikely(init_state_ip_map(state) < 0))
		return -1;
	if (unlikely(init_state_broadcast_arr(state) < 0))
		return -1;

	state->epoll_fd     = -1;
	state->tcp_fd       = -1;
	state->tun_fd       = -1;
	state->stop         = false;
	state->read_tun_c   = 0;
	state->write_tun_c  = 0;

	return 0;
}


static int init_iface(struct srv_tcp_state *state)
{
	int fd;
	struct iface_cfg i;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	fd = tun_alloc(j->dev, IFF_TUN | IFF_NO_PI);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	memset(&i, 0, sizeof(struct iface_cfg));
	strncpy(i.dev, j->dev, sizeof(i.dev) - 1);
	strncpy(i.ipv4, j->ipv4, sizeof(i.ipv4) - 1);
	strncpy(i.ipv4_netmask, j->ipv4_netmask, sizeof(i.ipv4_netmask) - 1);
	i.mtu = j->mtu;

	if (unlikely(!teavpn_iface_up(&i))) {
		pr_err("Cannot raise virtual network interface up");
		goto out_err;
	}

	state->tun_fd = fd;
	return 0;
out_err:
	close(fd);
	return -1;
}


static int socket_setup(int fd, struct srv_cfg *cfg)
{
	int rv;
	int err;
	int y;
	socklen_t len = sizeof(y);
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

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_INCOMING_CPU";
		goto out_err;
	}

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 2;
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
	int fd;
	int err;
	int retval;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;

	prl_notice(0, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		err = errno;
		retval = -err;
		pr_err("socket(): " PRERF, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);

	retval = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("bind(): " PRERF, PREAR(err));
		goto out_err;
	}

	retval = listen(fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("listen(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = fd;
	prl_notice(0, "Listening on %s:%u...", sock->bind_addr,
		   sock->bind_port);

	return retval;
out_err:
	if (fd > 0)
		close(fd);
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


static const char* resolve_new_client_ip(struct sockaddr_in *saddr,
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


static bool resolve_client_slot(int cli_fd, const char *src_ip,
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
	state->epoll_map[cli_fd] = idx + EPL_MAP_ADD;

	client = &state->clients[idx];
	client->is_used  = true;
	client->is_conn  = true;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;

	strncpy(client->src_ip, src_ip, IPV4_L - 1);
	client->src_ip[IPV4_L - 1] = '\0';

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

	if (likely(resolve_client_slot(cli_fd, src_ip, src_port, state)))
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


typedef enum _goto_in_client_event_t {
	CET_GT_RETURN_OK = 0,
	CET_GT_ERR = 1,
	CET_GT_CLOSE_CONN = 2,
} goto_cl_evt_t;


static void CORRUPTION_DUMP(void *ptr, size_t len)
{
	if ((NOTICE_MAX_LEVEL) >= 5) {
		panic("Data corrution detected!");
		VT_HEXDUMP(ptr, len);
	}
}


static void print_corruption_notice(struct client_slot *client)
{
	tcli_pkt_t *cli_pkt = client->recv_buf.__pkt_chk;
	CORRUPTION_DUMP(cli_pkt, sizeof(*cli_pkt));
}


static goto_cl_evt_t handle_iface_write()
{

}


static goto_cl_evt_t process_packet_from_client2(tcli_pkt_t *cli_pkt,
						 struct client_slot *client,
						 uint16_t data_len,
						 struct srv_tcp_state *state)
{
	tcli_pkt_type_t pkt_type = cli_pkt->type;

	
	if (likely(pkt_type == TCLI_PKT_IFACE_DATA))
		return handle_iface_write(state, cli_pkt, data_len);
	if (unlikely(pkt_type == TCLI_PKT_HELLO))
		return handle_hello_pkt(cli_pkt, data_len);
	if (unlikely(pkt_type == TCLI_PKT_AUTH))
		return CET_GT_RETURN_OK;
	if (unlikely(pkt_type == TCLI_PKT_IFACA_ACK))
		return CET_GT_RETURN_OK;
	if (unlikely(pkt_type == TCLI_PKT_REQSYNC))
		return CET_GT_RETURN_OK;
	if (unlikely(pkt_type == TCLI_PKT_PING))
		return CET_GT_RETURN_OK;
	if (unlikely(pkt_type == TCLI_PKT_CLOSE))
		return CET_GT_RETURN_OK;

	print_corruption_dump(client);

	prl_notice(0, "Client " PRWIU " sends invalid packet type (type: %d) "
		      "CORRUPTED PACKET?", W_IU(client), pkt_type);

	return client->is_auth ? CET_GT_ERR : CET_GT_CLOSE_CONN;
}


static goto_cl_evt_t process_packet_from_client(size_t recv_s,
						struct client_slot *client,
				   		struct srv_tcp_state *state)
{
	char *recv_buf;
	tcli_pkt_t *cli_pkt;

	uint8_t  npad;
	uint16_t data_len;
	size_t   fdata_len; /* Expected full data length + plus pad    */
	size_t   cdata_len; /* Current received data length + plus pad */
	goto_cl_evt_t retval;


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

		print_corruption_dump(client);

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

		return client->is_auth ? CET_GT_ERR : CET_GT_CLOSE_CONN;
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
	retval = process_packet_from_client2(cli_pkt, client, data_len, state);
	if (retval != CET_GT_RETURN_OK)
		return retval;

	if (likely(cdata_len > fdata_len)) {
		size_t processed_len;
		size_t unprocessed_len;
		char *source_ptr;

		processed_len   = TCLI_PKT_MIN_L + fdata_len;
		unprocessed_len = recv_s - processed_len;
		source_ptr      = &(recv_buf[processed_len]);

		recv_s = unprocessed_len;
		memmove(recv_buf, source_ptr, unprocessed_len);

		prl_notice(5, "memmove " PRWIU " (copy_size: %zu; "
			      "processed_len: %zu)",
			      W_IU(client), recv_s, processed_len);

		goto process_again;
	}

	recv_s = 0;
out:
	client->recv_s = recv_s;
	return CET_GT_RETURN_OK;
}


static goto_cl_evt_t
handle_incoming_packet_from_client(int cli_fd, struct client_slot *client,
				   struct srv_tcp_state *state)
{
	int err;
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
		err = errno;
		if (err == EAGAIN)
			return CET_GT_RETURN_OK;

		pr_err("recv(fd=%d): " PRERF " " PRWIU, cli_fd, PREAR(err),
		       W_IU(client));
		return CET_GT_ERR;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, PRWIU " has closed its connection", W_IU(client));
		return CET_GT_CLOSE_CONN;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "[%10" PRIu32 "] recv(fd=%d) %zd bytes from " PRWIU
		   " (recv_s = %zu)", client->recv_c, cli_fd, recv_ret,
		   W_IU(client), recv_s);

	return process_packet_from_client(recv_s, client, state);
}


static int handle_client_event(int cli_fd, uint16_t map_to,
			       struct srv_tcp_state *state, uint32_t revents)
{
	goto_cl_evt_t jump_to;
	struct client_slot *client = &state->clients[map_to];
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask)) {
		pr_err("Detected error from revents " PRWIU, W_IU(client));
		goto out_close_conn;
	}


	jump_to = handle_incoming_packet_from_client(cli_fd, client, state);
	if (likely(jump_to == CET_GT_RETURN_OK)) {
		goto out_return_ok;
	} else
	if (unlikely(jump_to == CET_GT_ERR)) {
		goto out_err;
	} else
	if (unlikely(jump_to == CET_GT_CLOSE_CONN)) {
		goto out_close_conn;
	} else {
		__builtin_unreachable();
	}

out_return_ok:
	return 0;

out_err:
	client->recv_s = 0;
	if (unlikely(client->err_c++ >= MAX_ERR_C)) {
		pr_err("Client " PRWIU " has reached the max number of errors",
		       W_IU(client));
		goto out_close_conn;
	}

	/* We tolerate small error */
	return 0;

out_close_conn:
	epoll_delete(state->epoll_fd, cli_fd);
	close(cli_fd);

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
		map_to -= EPL_MAP_ADD;
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
	free(state->bc_idx_arr.arr);
	memset(state, 0, sizeof(struct srv_tcp_state));
}


static void destroy_state(struct srv_tcp_state *state)
{
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

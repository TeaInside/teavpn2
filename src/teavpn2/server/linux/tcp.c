
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


typedef enum _evt_cli_goto_t {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_cli_goto_t;


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


static int accept_new_connection(int tcp_fd, struct srv_tcp_state *state)
{
	(void)tcp_fd;
	(void)state;

	return -1;
}


static int handle_tcp_event(int tcp_fd, struct srv_tcp_state *state,
			    uint32_t revents)
{
	const uint32_t err_mask = EPOLLERR | EPOLLHUP;

	if (unlikely(revents & err_mask))
		return -1;

	return accept_new_connection(tcp_fd, state);
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
(void)pop_client_stack;
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

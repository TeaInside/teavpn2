
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <teavpn2/server/auth.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/tcp.h>
#include <teavpn2/client/linux/tcp.h>

#define FDS_MAP_SIZE (65535)
#define FDS_ADD_NUM  (3)
#define MAX_ERR_C    (15)
#define EPOLL_INEVT  (EPOLLIN | EPOLLPRI | EPOLLRDHUP)

/* Ah, just short macros for printing... */
#define W_IP(CL) ((CL)->src_ip), ((CL)->src_port)
#define W_UN(CL) ((CL)->username)
#define W_IU(CL) W_IP(CL), W_UN(CL)
#define PRWIU "%s:%d (%s)"

typedef enum __fds_map {
	FDS_MAP_NOOP = 0,
	FDS_MAP_TUN  = 1,
	FDS_MAP_NET  = 2,
} _fds_map;


typedef enum __ctstate {
	CT_NEW		= 0,
	CT_ESTABLISHED	= 1,
	CT_NOSYNC	= 2,
	CT_DEAD		= 3,
} _ctstate;


struct srv_tcp_client {
	bool			is_used;
	bool			is_conn;
	bool			is_auth;
	char			username[255];
	char			src_ip[IPV4LEN + 1];
	uint16_t		src_port;
	uint16_t		arr_idx;
	int32_t			on_idx_i;
	int			cli_fd;
	_ctstate		ctstate;
	uint8_t			err_c;	 /* How many errors occured?   */
	uint32_t		send_c;	 /* How many calls to sys_send */
	uint32_t		recv_c;	 /* How many calls to sys_recv */
	uint16_t		recv_s;	 /* Active bytes in recv_buf   */
	uint32_t		in_ip;	 /* Private IP address         */
	cli_tcp_pkt_buf		buf;
};


struct _cl_stk {
	uint16_t		sp;
	uint16_t		max_sp;
	uint16_t		*arr;
};


struct srv_tcp_state {
	int			epl_fd;	/* epoll fd		*/
	int			tun_fd;	/* TUN/TAP fd		*/
	int			net_fd;	/* Main TCP socket fd	*/
	struct _cl_stk		cl_stk;
	uint16_t		on_idx_n;
	uint16_t		*on_idx_arr;
	uint16_t		*fds_map;
	struct srv_cfg		*cfg;
	struct srv_tcp_client	*clients;
	bool			stop;
	bool			has_wrq;
};


static struct srv_tcp_state *g_state;


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	prl_notice(0, "Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int32_t push_cl(struct _cl_stk *cl_stk, uint16_t val)
{
	uint16_t sp = cl_stk->sp;

	assert(sp > 0);
	cl_stk->arr[--sp] = val;
	cl_stk->sp = sp;
	return (int32_t)val;
}


static int32_t pop_cl(struct _cl_stk *cl_stk)
{
	int32_t val;
	uint16_t sp = cl_stk->sp;
	uint16_t max_sp = cl_stk->max_sp;

	/* sp must never be higher than max_sp */
	assert(sp <= max_sp);

	if (unlikely(sp == max_sp))
		return -1; /* There is nothing in the stack */

	val = (int32_t)cl_stk->arr[sp];
	cl_stk->sp = ++sp;
	return (int32_t)val;
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
		pr_error("epoll_ctl(EPOLL_CTL_ADD): " PRERR, PREAG(err));
		return -1;
	}

	return 0;
}


static int epoll_delete(int epl_fd, int fd)
{
	int err;

	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_DEL, fd, NULL) < 0)) {
		err = errno;
		pr_error("epoll_ctl(EPOLL_CTL_DEL): " PRERR, PREAG(err));
		return -1;
	}

	return 0;
}


static void tcp_client_init(struct srv_tcp_client *client, uint16_t idx)
{
	client->is_used     = false;
	client->is_conn     = false;
	client->is_auth     = false;
	client->username[0] = '_';
	client->username[1] = '\0';
	client->arr_idx     = idx;
	client->on_idx_i    = -1;
	client->cli_fd      = -1;
	client->ctstate     = CT_DEAD;
	client->err_c       = 0;
	client->recv_s      = 0;
	client->send_c      = 0;
	client->recv_c      = 0;
	client->in_ip       = 0;
	client->has_wrq	    = 0;
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	struct srv_cfg *cfg = state->cfg;
	struct _cl_stk *cl_stk = &state->cl_stk;
	uint16_t max_conn = cfg->sock.max_conn;
	uint16_t *on_idx_arr = NULL;
	uint16_t *fds_map = NULL;
	uint16_t *stack_arr = NULL;
	struct srv_tcp_client *clients = NULL;

	on_idx_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(on_idx_arr == NULL))
		goto out_err_calloc;

	stack_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(stack_arr == NULL))
		goto out_err_calloc;

	fds_map = calloc(FDS_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(fds_map == NULL))
		goto out_err_calloc;

	clients = calloc(max_conn, sizeof(struct srv_tcp_client));
	if (unlikely(clients == NULL))
		goto out_err_calloc;

	cl_stk->sp = max_conn;
	cl_stk->max_sp = max_conn;
	cl_stk->arr = stack_arr;

	for (uint16_t i = 0; i < max_conn; i++)
		tcp_client_init(clients + i, i);

	for (uint32_t i = 0; i < FDS_MAP_SIZE; i++)
		fds_map[i] = FDS_MAP_NOOP;

	for (uint16_t i = max_conn; i--;)
		push_cl(&state->cl_stk, i);

	state->stop = false;
	state->net_fd = -1;
	state->tun_fd = -1;
	state->epl_fd = -1;
	state->on_idx_n = 0;
	state->on_idx_arr = on_idx_arr;
	state->fds_map = fds_map;
	return 0;

out_err_calloc:
	err = errno;
	free(on_idx_arr);
	free(stack_arr);
	free(fds_map);
	pr_error("calloc: Cannot allocate memory: " PRERR, PREAG(err));
	return -ENOMEM;
}


static int init_iface(struct srv_tcp_state *state)
{
	int fd;
	struct iface_cfg i;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);
	fd = tun_alloc(j->dev, IFF_TUN);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	memset(&i, 0, sizeof(struct iface_cfg));
	strncpy(i.dev, j->dev, sizeof(i.dev) - 1);
	strncpy(i.ipv4, j->ipv4, sizeof(i.ipv4) - 1);
	strncpy(i.ipv4_netmask, j->ipv4_netmask, sizeof(i.ipv4_netmask) - 1);
	i.mtu = j->mtu;

	if (unlikely(!raise_up_interface(&i)))
		goto out_err;

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
	int y = 1;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	/*
	 * TODO: Utilize `cfg` to set some socket options from config
	 */
	(void)cfg;
	return rv;

out_err:
	err = errno;
	pr_error("setsockopt(): " PRERR, PREAG(err));
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
		pr_error("socket(): " PRERR, PREAG(err));
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
		pr_error("bind(): " PRERR, PREAG(err));
		goto out_err;
	}

	retval = listen(fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_error("listen(): " PRERR, PREAG(err));
		goto out_err;
	}

	state->net_fd = fd;
	prl_notice(0, "Listening on %s:%u...", sock->bind_addr,
		   sock->bind_port);

	return retval;
out_err:
	if (fd > 0)
		close(fd);
	return retval;
}


static int init_epoll(struct srv_tcp_state *state)
{
	int err;
	int epl_fd;
	int retval;
	uint16_t *fds_map = state->fds_map;

	prl_notice(0, "Initializing epoll fd...");

	epl_fd = epoll_create((int)state->cfg->sock.max_conn);
	if (unlikely(epl_fd < 0)) {
		err = errno;
		retval = epl_fd;
		pr_error("epoll_create(): " PRERR, PREAG(err));
		goto out_err;
	}

	fds_map[state->tun_fd] = FDS_MAP_TUN;
	retval = epoll_add(epl_fd, state->tun_fd, EPOLL_INEVT);
	if (unlikely(retval < 0))
		goto out_err_epctl;

	fds_map[state->net_fd] = FDS_MAP_NET;
	retval = epoll_add(epl_fd, state->net_fd, EPOLL_INEVT);
	if (unlikely(retval < 0))
		goto out_err_epctl;

	state->epl_fd = epl_fd;
	return 0;

out_err_epctl:
	err = errno;
	pr_error("epoll_ctl(): " PRERR, PREAG(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return retval;
}


static uint16_t add_online_cl_idx(struct srv_tcp_state *state, uint16_t idx)
{
	uint16_t n = state->on_idx_n++;
	state->on_idx_arr[n] = idx;
	return n;
}


static void remove_online_cl_idx(struct srv_tcp_state *state, uint16_t idx)
{
	uint16_t n = state->on_idx_n;
	uint16_t *on_idx_arr = state->on_idx_arr;

	/* Removing index beyond the used data makes no sense */
	assert(idx < n);

	if (idx != (n - 1)) {
		memmove(on_idx_arr + idx, on_idx_arr + idx + 1,
			(n - idx - 1) * sizeof(uint16_t));
	}

	state->on_idx_n--;
}


static void accept_conn(int net_fd, int epl_fd, struct srv_tcp_state *state)
{
	int err;
	int cli_fd;
	int32_t ridx;
	uint16_t idx;
	uint16_t sport;
	const char *sip;
	char buf[IPV4LEN + 1];
	struct sockaddr_in addr;
	struct srv_tcp_client *client;
	const uint32_t epl_evt = EPOLL_INEVT;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(&addr, 0, addrlen);
	cli_fd = accept(net_fd, &addr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("accept(): " PRERR, PREAG(err));
		return;
	}

	/* Get readable source IP address */
	sip = inet_ntop(AF_INET, &addr.sin_addr, buf, IPV4LEN);
	if (unlikely(sip == NULL)) {
		err = errno;
		pr_error("inet_ntop(%u): " PRERR, addr.sin_addr.s_addr,
			 PREAG(err));
		goto out_close;
	}

	/* Get readable source port */
	sport = ntohs(addr.sin_port);

	if (unlikely(cli_fd > (FDS_MAP_SIZE - 1))) {
		pr_error("Cannot accept new connection from %s:%u because "
			 "returned fd from accept() is too big "
			 "(FDS_MAP_SIZE = %d, returned fd = %d)", sip, sport,
			 FDS_MAP_SIZE, cli_fd);
		goto out_close;
	}

	ridx = pop_cl(&state->cl_stk);
	if (unlikely(ridx == -1)) {
		prl_notice(1, "Client slot is full, can't accept connection");
		prl_notice(1, "Dropping connection from %s:%u", sip, sport);
		goto out_close;
	}

	/* Welcome new connection :) */
	idx = (uint16_t)ridx;
	if (unlikely(epoll_add(epl_fd, cli_fd, epl_evt) < 0)) {
		pr_error("Cannot accept new connection from %s:%u because of "
			 "error on epoll_add()", sip, sport);
		goto out_close;
	}

	state->fds_map[cli_fd] = idx + FDS_ADD_NUM;

	client = &state->clients[idx];
	client->is_used  = true;
	client->is_conn  = true;
	client->ctstate  = CT_NEW;
	client->cli_fd   = cli_fd;
	client->src_port = sport;
	strncpy(client->src_ip, sip, IPV4LEN);
	assert(client->arr_idx == idx);

	prl_notice(1, "New connection from %s:%u (fd:%d)", sip, sport, cli_fd);
	return;

out_close:
	close(cli_fd);
}


static void handle_recv_client(int cli_fd, int map, struct srv_tcp_state *state)
{
	int err;
	char *recv_buf;
	size_t recv_s; /* Current active bytes in recv_buf */
	size_t recv_len;
	ssize_t recv_ret;
	uint16_t arr_idx;
	int32_t on_idx_i;
	struct srv_tcp_client *client = &state->clients[map];

	recv_s   = client->recv_s;
	recv_buf = client->buf.raw;

	client->recv_c++;
	recv_len = CLI_PKT_RECVL - recv_s;

	recv_ret = recv(cli_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("recv(): " PRERR " " PRWIU, PREAG(err), W_IU(client));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, PRWIU " has closed its connection", W_IU(client));
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;
	prl_notice(15, "[%010" PRIu32 "] recv() %ld bytes from " PRWIU
		       " (recv_s = %zu)", client->recv_c, recv_ret,
		       W_IU(client), recv_s);

	// switch (process_client_buf(recv_s, client, state)) {
	// 	case RETURN_OK:
	// 		return;
	// 	case OUT_CONN_ERR:
	// 		goto out_err_c;
	// 	case OUT_CONN_CLOSE:
	// 		goto out_close_conn;
	// }

out_err_c:
	client->recv_s = 0;
	if (unlikely(client->err_c++ >= MAX_ERR_C)) {
		prl_notice(0, "Connection " PRWIU " reached the max number of "
			   "error", W_IU(client));
		goto out_close_conn;
	}
	return;

out_close_conn:
	arr_idx  = client->arr_idx;
	on_idx_i = client->on_idx_i;

	epoll_delete(state->epl_fd, cli_fd);
	close(cli_fd);
	push_cl(&state->cl_stk, arr_idx);
	tcp_client_init(client, arr_idx);

	if (on_idx_i != -1)
		remove_online_cl_idx(state, on_idx_i);

	prl_notice(0, "Closing connection fd from " PRWIU, W_IU(client));
	return;
}


static int event_loop(struct srv_tcp_state *state)
{
	int err;
	int epl_ret;
	int retval = 0;
	int maxevents = 32;
	int epl_fd = state->epl_fd;
	uint16_t *fds_map = state->fds_map;
	struct epoll_event events[32];

	const uint32_t errev = EPOLLERR | EPOLLHUP; /* Error events */

	while (likely(state->stop)) {
		epl_ret = epoll_wait(epl_fd, events, maxevents, 3000);

		if (unlikely(epl_ret == 0)) {
			/*
			 * epoll reached timeout.
			 *
			 * TODO: Do something meaningful here...
			 * Maybe keep alive ping to clients?
			 */
			continue;
		}

		if (unlikely(epl_ret < 0)) {
			err = errno;
			if (err == EINTR) {
				retval = 0;
				prl_notice(0, "Interrupted!");
				break;
			}

			retval = -err;
			pr_error("epoll_wait(): " PRERR, PREAG(err));
			break;
		}

		for (int i = 0; likely(i < epl_ret); i++) {
			struct epoll_event *evp = &events[i];
			uint16_t map;
			int fd = evp->data.fd;
			uint32_t events = evp->events;
			bool is_err = ((events & errev) != 0);
#ifndef NDEBUG
			if (unlikely(fd > FDS_MAP_SIZE)) {
				pr_error("fd > FDS_MAP_SIZE");
				pr_error("But at %s:%d", __FILE__, __LINE__);
				abort(); /* Must be a bug */
			}
#endif
			map = fds_map[fd];

			switch (map) {
			case FDS_MAP_NOOP:
#ifndef NDEBUG
				pr_error("But at %s:%d", __FILE__, __LINE__);
				abort(); /* Must be a bug */
#endif
				break;
			case FDS_MAP_TUN:
				if (unlikely(is_err)) {
					pr_error("FDS_MAP_TUN error");
					retval = -1;
					goto out;
				}
				break;
			case FDS_MAP_NET:
				if (unlikely(is_err)) {
					pr_error("FDS_MAP_NET error");
					retval = -1;
					goto out;
				}
				accept_conn(fd, epl_fd, state);
				break;
			default:
				if (unlikely(is_err)) {
					pr_error("Client error (fd:%d)", fd);
					retval = -1;
					goto out;
				}
				handle_recv_client(fd, map - FDS_ADD_NUM, state);
				break;
			}
		}
	}
out:
	return retval;
}


static void destroy_state(struct srv_tcp_state *state)
{
	int epl_fd = state->epl_fd;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct srv_tcp_client *client;
	struct srv_tcp_client *clients = state->clients;

	if (likely(tun_fd != -1)) {
		prl_notice(6, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(net_fd != -1)) {
		prl_notice(6, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	if (likely(epl_fd != -1)) {
		prl_notice(6, "Closing state->epl_fd (%d)", epl_fd);
		close(epl_fd);
	}

	while (likely(max_conn--)) {
		client = clients + max_conn;
		if (client->is_used) {
			prl_notice(6, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);
		}
	}

	free(clients);
	free(state->on_idx_arr);
	free(state->fds_map);
	free(state->cl_stk.arr);
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, intr_handler);
	signal(SIGINT, intr_handler);
	signal(SIGPIPE, intr_handler);
	signal(SIGTERM, intr_handler);
	signal(SIGQUIT, intr_handler);

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


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


#define FDS_MAP_ADD  (5)
#define TUN_MAP_IDX  (3)
#define NET_MAP_IDX  (2)
#define PIPE_MAP_IDX (1)
#define FDS_MAP_NOOP (0)
#define FDS_MAP_SIZE (65535)
#define EPOLL_INEVT  (EPOLLIN | EPOLLPRI | EPOLLRDHUP)
#define MAX_ERR_C (15)

typedef enum {
	RETURN_OK = 0,
	OUT_CONN_ERR = 1,
	OUT_CONN_CLOSE = 2,
} evt_loop_goto;

/* Ah, just short macros for printing... */
#define W_IP(CL) ((CL)->src_ip), ((CL)->src_port)
#define W_UN(CL) ((CL)->username)
#define W_IU(CL) W_IP(CL), W_UN(CL)
#define PRWIU "%s:%d (%s)"

typedef enum {
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
	int32_t			on_idx_i; /* Which on_idx index am I stored? */
	int			cli_fd;
	_ctstate		ctstate;
	uint8_t			err_c;	 /* How many errors occured?   */
	uint32_t		send_c;	 /* How many calls to sys_send */
	uint32_t		recv_c;	 /* How many calls to sys_recv */
	uint16_t		recv_s;	 /* Active bytes in recv_buf   */
	uint32_t		in_ip;	 /* Private IP address         */
	union {
		char			recv_buf[sizeof(struct cli_tcp_pkt)];
		struct cli_tcp_pkt	cli_pkt;
	};
};


struct _cl_stk {
	uint16_t		sp;
	uint16_t		max_sp;
	uint16_t		*arr;
};


struct srv_tcp_state {
	int			net_fd;	/* Main TCP socket fd	*/
	int			tun_fd;	/* TUN/TAP fd		*/
	int			epl_fd;	/* epoll fd		*/
	int			pipe_fd[2];
	uint16_t		on_idx_n;
	uint16_t		*on_idx;  /* Online fd */
	int			*fds_map; /* Map client fd to clients array */
	uint16_t		max_conn;
	struct srv_cfg		*cfg;
	struct srv_tcp_client	*clients;
	struct _cl_stk		cl_stk;
	bool			stop;
	union {
		char			send_buf[sizeof(struct srv_tcp_pkt)];
		struct srv_tcp_pkt	srv_pkt;
	};
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
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	int *fds_map = NULL;
	uint16_t *on_idx = NULL;
	uint16_t *cl_stk = NULL;
	struct srv_tcp_client *clients = NULL;
	uint16_t max_conn = state->cfg->sock.max_conn;

	prl_notice(0, "Initializing main state...");

	fds_map = calloc(FDS_MAP_SIZE, sizeof(int));
	if (unlikely(fds_map == NULL))
		goto out_err_calloc;

	on_idx = calloc(max_conn, sizeof(int));
	if (unlikely(on_idx == NULL))
		goto out_err_calloc;

	cl_stk = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(cl_stk == NULL))
		goto out_err_calloc;

	clients = calloc(max_conn, sizeof(struct srv_tcp_client));
	if (unlikely(clients == NULL))
		goto out_err_calloc;

	state->cl_stk.sp = max_conn;
	state->cl_stk.max_sp = max_conn;
	state->cl_stk.arr = cl_stk;

	for (uint16_t i = 0; i < max_conn; i++)
		tcp_client_init(clients + i, i);

	for (uint16_t i = max_conn; i--;)
		push_cl(&state->cl_stk, i);

	for (uint32_t i = 0; i < FDS_MAP_SIZE; i++)
		fds_map[i] = FDS_MAP_NOOP;

	state->stop = false;
	state->net_fd = -1;
	state->tun_fd = -1;
	state->epl_fd = -1;
	state->pipe_fd[0] = -1;
	state->pipe_fd[1] = -1;
	state->on_idx_n = 0;
	state->on_idx = on_idx;
	state->fds_map = fds_map;
	state->clients = clients;
	state->max_conn = max_conn;
	return 0;

out_err_calloc:
	err = errno;
	free(fds_map);
	free(on_idx);
	free(cl_stk);
	pr_error("calloc(): Cannot allocate memory: " PRERR, PREAG(err));
	return -1;
}


static int init_pipe(struct srv_tcp_state *state)
{
	int err;

	prl_notice(6, "Initializing pipe...");
	if (unlikely(pipe(state->pipe_fd) < 0)) {
		err = errno;
		pr_error("pipe(): " PRERR, PREAG(err));
		return -err;
	}

	prl_notice(6, "Pipe has been successfully created!");
	prl_notice(6, "state->pipe_fd[0] = %d", state->pipe_fd[0]);
	prl_notice(6, "state->pipe_fd[1] = %d", state->pipe_fd[1]);

	return 0;
}


static int init_iface(struct srv_tcp_state *state)
{
	int fd;
	struct iface_cfg i;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(3, "Creating virtual network interface: \"%s\"...", j->dev);
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

	prl_notice(3, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		err = errno;
		retval = -err;
		pr_error("socket(): " PRERR, PREAG(err));
		goto out_err;
	}

	prl_notice(3, "Setting up socket file descriptor...");
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
	int *fds_map = state->fds_map;

	prl_notice(2, "Initializing epoll fd");

	epl_fd = epoll_create((int)state->max_conn);
	if (unlikely(epl_fd < 0)) {
		err = errno;
		retval = epl_fd;
		pr_error("epoll_create(): " PRERR, PREAG(err));
		goto out_err;
	}

	fds_map[state->tun_fd] = TUN_MAP_IDX;
	retval = epoll_add(epl_fd, state->tun_fd, EPOLL_INEVT);
	if (unlikely(retval < 0))
		goto out_err_epctl;

	fds_map[state->net_fd] = NET_MAP_IDX;
	retval = epoll_add(epl_fd, state->net_fd, EPOLL_INEVT);
	if (unlikely(retval < 0))
		goto out_err_epctl;

#if 0
	fds_map[state->pipe_fd[0]] = PIPE_MAP_IDX;
	retval = epoll_add(epl_fd, state->pipe_fd[0], EPOLLIN);
	if (unlikely(retval < 0))
		goto out_err_epctl;
#endif

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
	state->on_idx[n] = idx;
	return n;
}


static void remove_online_cl_idx(struct srv_tcp_state *state, uint16_t idx)
{
	uint16_t n = state->on_idx_n;
	uint16_t *on_idx = state->on_idx;

	/* Removing index beyond the used data makes no sense */
	assert(idx < n);

	if (idx != (n - 1)) {
		memmove(on_idx + idx, on_idx + idx + 1,
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

	state->fds_map[cli_fd] = (int)idx + FDS_MAP_ADD;

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


static ssize_t send_to_client(struct srv_tcp_client *client,
			      const struct srv_tcp_pkt *srv_pkt,
			      size_t send_len)
{
	int err;
	ssize_t send_ret;

again:
	send_ret = send(client->cli_fd, srv_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		client->err_c++;
		err = errno;
		if (err == EAGAIN)
			goto again;

		pr_error("send() to " PRWIU ": " PRERR, W_IP(client),
			 client->username, PREAG(err));
		return -1;
	}
	client->send_c++;

	prl_notice(11, "[%010" PRIu32 "] send() %ld bytes to " PRWIU,
		   client->send_c, send_ret, W_IU(client));

	return send_ret;
}


static bool send_server_banner(struct srv_tcp_client *client,
			       struct srv_tcp_state *state)
{
	size_t send_len;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	srv_pkt->type   = SRV_PKT_BANNER;
	srv_pkt->length = htons(sizeof(struct srv_banner));

	srv_pkt->banner.cur.ver = 0;
	srv_pkt->banner.cur.sub_ver = 0;
	srv_pkt->banner.cur.sub_sub_ver = 1;

	srv_pkt->banner.min.ver = 0;
	srv_pkt->banner.min.sub_ver = 0;
	srv_pkt->banner.min.sub_sub_ver = 1;

	srv_pkt->banner.max.ver = 0;
	srv_pkt->banner.max.sub_ver = 0;
	srv_pkt->banner.max.sub_sub_ver = 1;

	send_len = SRV_PKT_MIN_RSIZ + sizeof(struct srv_banner);
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static bool send_auth_ok(struct srv_tcp_client *client,
			 struct srv_tcp_state *state)
{
	size_t send_len;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	srv_pkt->type   = SRV_PKT_AUTH_OK;
	srv_pkt->length = htons(sizeof(struct srv_auth_ok));

	send_len = SRV_PKT_MIN_RSIZ + sizeof(struct srv_auth_ok);
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static bool send_auth_reject(struct srv_tcp_client *client,
			     struct srv_tcp_state *state)
{
	size_t send_len;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;

	srv_pkt->type   = SRV_PKT_AUTH_REJECT;
	srv_pkt->length = 0;

	send_len = SRV_PKT_MIN_RSIZ;
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static void auth_ok_notice(struct iface_cfg *iface,
			   struct srv_tcp_client *client)
{

	prl_notice(0, "Authentication success from " PRWIU, W_IU(client));

	prl_notice(0, "Assign IP %s %s to " PRWIU, iface->ipv4,
		   iface->ipv4_netmask, W_IU(client));
}


static int handle_auth(struct srv_tcp_client *client,
		       struct srv_tcp_state *state)
{
	uint16_t arr_idx = client->arr_idx;
	struct cli_tcp_pkt *cli_pkt = &client->cli_pkt;
	struct auth_pkt *auth = &cli_pkt->auth;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;
	struct srv_auth_ok *auth_ok = &srv_pkt->auth_ok;
	struct iface_cfg *iface = &auth_ok->iface;

	auth->username[sizeof(auth->username) - 1] = '\0';
	auth->password[sizeof(auth->password) - 1] = '\0';

	strncpy(client->username, auth->username, 0xffu - 1u);
	prl_notice(0, "Receive authentication from " PRWIU, W_IU(client));

	if (likely(teavpn_server_get_auth(iface, auth, state->cfg))) {
		if (likely(send_auth_ok(client, state))) {
			auth_ok_notice(iface, client);
			client->is_auth = true;
			client->on_idx_i = add_online_cl_idx(state, arr_idx);
			return true;
		} else {
			prl_notice(0, "Authentication error from " PRWIU,
				   W_IU(client));
			goto out_fail;
		}
	}

	prl_notice(0, "Authentication failed from " PRWIU, W_IU(client));

out_fail:
	send_auth_reject(client, state);
	return false;
}


static bool handle_iface_write(struct srv_tcp_state *state,
			       struct cli_tcp_pkt *cli_pkt,
			       uint16_t fdata_len)
{
	ssize_t write_ret;
	int tun_fd = state->tun_fd;

	write_ret = write(tun_fd, cli_pkt->raw_data, fdata_len);
	if (unlikely(write_ret < 0)) {
		pr_error("write(): %s", strerror(errno));
		return false;
	}
	prl_notice(11, "write() %ld bytes to tun_fd", write_ret);

	return true;
}


static void handle_iface_read(int tun_fd, struct srv_tcp_state *state)
{
	int err;
	size_t send_len;
	ssize_t read_ret;
	uint16_t *on_idx;
	uint16_t on_idx_n;
	struct srv_tcp_client *clients = state->clients;
	struct srv_tcp_pkt *srv_pkt = &state->srv_pkt;
	char *buf = srv_pkt->raw_data;

	read_ret = read(tun_fd, buf, 4096);
	if (unlikely(read_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;

		state->stop = true;
		pr_error("read(tun_fd): " PRERR, PREAG(err));
		return;
	}
	prl_notice(11, "read() %ld bytes from tun_fd", read_ret);

	srv_pkt->type   = SRV_PKT_DATA;
	srv_pkt->length = htons((uint16_t)read_ret);

	send_len = SRV_PKT_MIN_RSIZ + (uint16_t)read_ret;

	on_idx = state->on_idx;
	on_idx_n = state->on_idx_n;
	for (uint16_t i = 0; i < on_idx_n; i++) {
		struct srv_tcp_client *client = clients + on_idx[i];

		assert(client->on_idx_i == i);
		send_to_client(client, srv_pkt, send_len);
	}
}


static evt_loop_goto process_client_buf(size_t recv_s,
					struct srv_tcp_client *client,
					struct srv_tcp_state *state)
{
	uint16_t fdata_len; /* Full data length             */
	uint16_t cdata_len; /* Current received data length */
	struct cli_tcp_pkt *cli_pkt = &client->cli_pkt;
	char *recv_buf = client->recv_buf;

again:
	if (unlikely(recv_s < CLI_PKT_MIN_RSIZ)) {
		/*
		 * We haven't received the type and length of packet.
		 * It very unlikely happens, maybe connection is too
		 * slow or the extra data after memmove (?)
		 */
		goto out;
	}

	fdata_len = ntohs(cli_pkt->length);
	if (unlikely(fdata_len > CLI_PKT_DATA_SIZ)) {
		/*
		 * fdata_length must never be greater than SRV_PKT_DATA_SIZ.
		 * Corrupted packet?
		 */
		prl_notice(1, "Client " PRWIU " sends invalid packet length "
			      "(max_allowed_len = %zu; srv_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", W_IU(client),
			      SRV_PKT_DATA_SIZ, fdata_len, recv_s);

		return OUT_CONN_ERR;
	}

	/* Calculate current data length */
	cdata_len = recv_s - CLI_PKT_MIN_RSIZ;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We've received the type and length of packet.
		 *
		 * However, the packet has not been fully received.
		 * So let's wait for the next cycle to process it.
		 */
		goto out;
	}

	prl_notice(15, "==== Process the packet " PRWIU, W_IU(client));

	switch (cli_pkt->type) {
	case CLI_PKT_HELLO:
		/* Only handle hello from not a new client */
		if (unlikely(client->ctstate != CT_NEW))
			break;

		/* Welcome new conenction with server banner */
		client->ctstate = CT_ESTABLISHED;
		if (unlikely(!send_server_banner(client, state)))
			return OUT_CONN_CLOSE;

		break;

	case CLI_PKT_AUTH:
		/* New connection must hello first before send auth */
		if (unlikely(client->ctstate == CT_NEW))
			return OUT_CONN_CLOSE;

		/* Ignore auth packet if the client has been authenticated */
		if (unlikely(client->is_auth))
			break;

		if (!handle_auth(client, state))
			return OUT_CONN_CLOSE; /* Sorry, wrong credential */

		break;

	case CLI_PKT_DATA:

		/* Unauthenticated client trying to send data */
		if (unlikely(!client->is_auth))
			return OUT_CONN_CLOSE;

		handle_iface_write(state, cli_pkt, fdata_len);
		break;

	case CLI_PKT_CLOSE:
		return OUT_CONN_CLOSE;

	default:
		/*
		 * TODO: Change the state to CT_NOSYNC and
		 *       create a recovery rountine.
		 */
		prl_notice(11, "Received invalid packet from " PRWIU
			       " (type: %d)", W_IU(client), cli_pkt->type);

		if (likely(!client->is_auth))
			return OUT_CONN_CLOSE;

		return OUT_CONN_ERR;
	}

	prl_notice(15, "cdata_len = %u; fdata_len = %u", cdata_len, fdata_len);

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra packet on the tail, must memmove to
		 * the head before we run out of buffer.
		 */
		size_t cur_valid_size = CLI_PKT_MIN_RSIZ + fdata_len;

		recv_s -= cur_valid_size;
		memmove(recv_buf, recv_buf + cur_valid_size, recv_s);

		prl_notice(15, "memmove " PRWIU " (copy_size: %zu; "
			       "recv_s: %zu; cur_valid_size: %zu)",
			       W_IU(client), recv_s, recv_s, cur_valid_size);

		goto again;
	}

	recv_s = 0;
out:
	client->recv_s = recv_s;
	return RETURN_OK;
}


static void handle_client(int cli_fd, int map, struct srv_tcp_state *state)
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
	recv_buf = client->recv_buf;

	client->recv_c++;
	recv_len = CLI_PKT_RSIZE - recv_s;
	prl_notice(0, "recv_len = %zu", recv_len);
	recv_ret = recv(cli_fd, recv_buf + recv_s, recv_len, 0);
	prl_notice(0, "recv_ret = %ld", recv_ret);

	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("recv(): " PRERR " " PRWIU, PREAG(err), W_IU(client));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(3, PRWIU " has closed its connection", W_IU(client));
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;
	prl_notice(15, "[%010" PRIu32 "] recv() %ld bytes from " PRWIU
		       " (recv_s = %zu)", client->recv_c, recv_ret,
		       W_IU(client), recv_s);

	switch (process_client_buf(recv_s, client, state)) {
		case RETURN_OK:
			return;
		case OUT_CONN_ERR:
			goto out_err_c;
		case OUT_CONN_CLOSE:
			goto out_close_conn;
	}

out_err_c:
	client->recv_s = 0;
	if (unlikely(client->err_c++ >= MAX_ERR_C)) {
		prl_notice(3, "Connection " PRWIU " reached the max number of "
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
	prl_notice(3, "Closing connection fd from " PRWIU, W_IU(client));
	return;
}


static int event_loop(struct srv_tcp_state *state)
{
	int err;
	int ret;
	int retval = 0;
	int maxevents = 50;
	int epl_fd = state->epl_fd;
	int *fds_map = state->fds_map;
	struct epoll_event events[50];
	// const uint32_t inev  = EPOLLIN | EPOLLPRI;  /* Input events    */
	const uint32_t errev = EPOLLERR | EPOLLHUP; /* Error events    */

	while (likely(!state->stop)) {
		ret = epoll_wait(epl_fd, events, maxevents, 3000);

		if (unlikely(ret == 0)) {
			/*
			 * epoll reached timeout.
			 *
			 * TODO: Do something meaningful here...
			 * Maybe keep alive ping to clients?
			 */
			continue;
		}

		if (unlikely(ret < 0)) {
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

		for (int i = 0; i < ret; i++) {
			struct epoll_event *evp = &events[i];
			int map;
			int fd = evp->data.fd;
			bool is_err = ((evp->events & errev) != 0);
#ifndef NDEBUG
			if (unlikely(fd > FDS_MAP_SIZE)) {
				pr_error("fd > FDS_MAP_SIZE");
				abort(); /* Must be a bug */
			}
#endif
			map = fds_map[fd];
			switch (map) {
			case FDS_MAP_NOOP:
				/* Bug? */
				break;
			case PIPE_MAP_IDX:
				break;
			case NET_MAP_IDX:
				if (unlikely(is_err)) {
					pr_error("NET_MAP_IDX error");
					retval = -1;
					goto out;
				}

				/* Someone is trying to connect to us. */
				accept_conn(fd, epl_fd, state);
				break;
			case TUN_MAP_IDX:
				if (unlikely(is_err)) {
					pr_error("TUN_MAP_IDX error");
					retval = -1;
					goto out;
				}

				handle_iface_read(fd, state);
				break;
			default:
				if (unlikely(is_err)) {
					pr_error("Client error (fd:%d)", fd);
					retval = -1;
					goto out;
				}

				handle_client(fd, map - FDS_MAP_ADD, state);
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
	int *pipe_fd = state->pipe_fd;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct srv_tcp_client *client;
	struct srv_tcp_client *clients = state->clients;

	if (likely(pipe_fd[0] != -1)) {
		prl_notice(6, "Closing state->pipe_fd[0] (%d)", pipe_fd[0]);
		close(pipe_fd[0]);
	}

	if (likely(pipe_fd[1] != -1)) {
		prl_notice(6, "Closing state->pipe_fd[1] (%d)", pipe_fd[1]);
		close(pipe_fd[1]);
	}

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

	while (max_conn--) {
		client = clients + max_conn;
		if (client->is_used) {
			prl_notice(6, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);
		}
	}

	free(clients);
	free(state->on_idx);
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
	retval = init_pipe(&state);
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

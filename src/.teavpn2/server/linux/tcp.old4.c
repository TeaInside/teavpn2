
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <stdalign.h>
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
#define EPOLL_INEVT  (EPOLLIN | EPOLLPRI)

/* Macros for printing */
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


typedef enum _evt_cli_goto {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_cli_goto;


struct srv_tcp_client {
	bool			is_used;
	bool			is_conn;
	bool			is_auth;
	bool			iface_acked;
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

	alignas(16) cli_tcp_pkt_buf		recv_buf;
	alignas(16) srv_tcp_pkt_buf		send_buf;
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
	uint32_t		read_c;
	uint32_t		write_c;
	struct _cl_stk		cl_stk;
	uint16_t		on_idx_n;
	uint16_t		*on_idx_arr;
	uint16_t		*fds_map;
	struct srv_cfg		*cfg;
	struct srv_tcp_client	*clients;
	bool			stop;
	srv_tcp_pkt_buf		srv_pkt;
};


static struct srv_tcp_state *g_state; /* Only for interrupt access */


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	prl_notice(0, "Signal %d (%s) has been caught", sig, strsignal(sig));
}


static void tcp_client_init(struct srv_tcp_client *client, uint16_t idx)
{
	client->is_used     = false;
	client->is_conn     = false;
	client->is_auth     = false;
	client->iface_acked = false;
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

	if (unlikely(sp == max_sp)) {
		/* There is nothing on the stack */
		return -1;
	}

	val = (int32_t)cl_stk->arr[sp];
	cl_stk->sp = ++sp;
	return (int32_t)val;
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	cpu_set_t affinity;
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
	state->read_c = 0;
	state->write_c = 0;
	state->on_idx_n = 0;
	state->on_idx_arr = on_idx_arr;
	state->fds_map = fds_map;
	state->clients = clients;

	CPU_ZERO(&affinity);
	CPU_SET(0, &affinity);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &affinity) < 0) {
		err = errno;
		pr_error("sched_setaffinity: " PRERR, PREAG(err));
	}

	errno = 0;
	if (nice(-20)) {
		err = errno;
		if (err != 0)
			pr_error("nice: " PRERR, PREAG(err));
	}

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
	int y;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 5000;
	rv = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, pv, len);
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


static int init_epoll(struct srv_tcp_state *state)
{
	int err;
	int epl_fd;
	int retval;
	uint16_t *fds_map = state->fds_map;

	prl_notice(0, "Initializing epoll fd...");

	epl_fd = epoll_create((int)state->cfg->sock.max_conn + 3);
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


static bool resolve_new_conn(int cli_fd, struct sockaddr_in *addr,
			     struct srv_tcp_state *state)
{
	int err;
	uint16_t sport;
	const char *sip;
	char buf[IPV4LEN + 1];

	uint16_t idx;
	int32_t ret_idx;
	struct srv_tcp_client *client;

	/* Get readable source IP address */
	sip = inet_ntop(AF_INET, &addr->sin_addr, buf, IPV4LEN);
	if (unlikely(sip == NULL)) {
		err = errno;
		pr_error("inet_ntop(%u): " PRERR, addr->sin_addr.s_addr,
			 PREAG(err));
		return false;
	}

	/* Get readable source port */
	sport = ntohs(addr->sin_port);

	if (unlikely(cli_fd > (FDS_MAP_SIZE - 1))) {
		pr_error("Cannot accept new connection from %s:%u because "
			 "returned fd from accept() is too big "
			 "(FDS_MAP_SIZE = %d, returned fd = %d)", sip, sport,
			 FDS_MAP_SIZE, cli_fd);
		return false;
	}

	ret_idx = pop_cl(&state->cl_stk);
	if (unlikely(ret_idx == -1)) {
		prl_notice(0, "Client slot is full, can't accept connection");
		prl_notice(0, "Dropping connection from %s:%u", sip, sport);
		return false;
	}

	/* Welcome new connection :) */
	idx = (uint16_t)ret_idx;
	if (unlikely(epoll_add(state->epl_fd, cli_fd, EPOLL_INEVT) < 0)) {
		pr_error("Cannot accept new connection from %s:%u because of "
			 "error on epoll_add()", sip, sport);
		return false;
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

	prl_notice(0, "New connection from %s:%u (fd:%d)", sip, sport, cli_fd);
	return true;
}


static void accept_new_conn(int net_fd, struct srv_tcp_state *state)
{
	int err;
	int cli_fd;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	prl_notice(0, "Accepting new connection...");

	memset(&addr, 0, addrlen);
	cli_fd = accept(net_fd, &addr, &addrlen);
	if (cli_fd < 0) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("accept(): " PRERR, PREAG(err));
		return;
	}

	if (!resolve_new_conn(cli_fd, &addr, state))
		close(cli_fd);
}


static ssize_t send_to_client(struct srv_tcp_client *client,
			      struct srv_tcp_pkt *srv_pkt,
			      size_t send_len)
{
	int err;
	ssize_t send_ret;
	int cli_fd = client->cli_fd;

	client->send_c++;
	srv_pkt->pad_n = 0;
	send_ret       = send(cli_fd, srv_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/* TODO: Handle pending buffer.
			 *
			 * Let it fallthrough at the moment.
			 */
		}

		client->err_c++;
		pr_error("send(fd=%d) to " PRWIU ": " PRERR, cli_fd,
			 W_IU(client), PREAG(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %ld bytes to " PRWIU,
		   client->send_c, cli_fd, send_ret, W_IU(client));
	return send_ret;
}


static bool send_server_banner(struct srv_tcp_client *client)
{
	size_t send_len;
	uint16_t data_len;
	struct srv_tcp_pkt *srv_pkt = client->send_buf.__pkt_chk;

	data_len        = sizeof(struct srv_banner);
	srv_pkt->type   = SRV_PKT_BANNER;
	srv_pkt->length = htons(data_len);

	srv_pkt->banner.cur.ver = 0;
	srv_pkt->banner.cur.sub_ver = 0;
	srv_pkt->banner.cur.sub_sub_ver = 1;

	srv_pkt->banner.min.ver = 0;
	srv_pkt->banner.min.sub_ver = 0;
	srv_pkt->banner.min.sub_sub_ver = 1;

	srv_pkt->banner.max.ver = 0;
	srv_pkt->banner.max.sub_ver = 0;
	srv_pkt->banner.max.sub_sub_ver = 1;

	send_len = SRV_PKT_MIN_L + data_len;
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static evt_cli_goto handle_hello(struct srv_tcp_client *client)
{
	if (client->is_auth)
		return RETURN_OK;

	return send_server_banner(client) ? RETURN_OK : OUT_CONN_CLOSE;
}


static bool send_auth_ok(struct srv_tcp_client *client)
{
	size_t send_len;
	uint16_t data_len;
	struct srv_tcp_pkt *srv_pkt = client->send_buf.__pkt_chk;

	data_len        = sizeof(struct srv_auth_ok);
	srv_pkt->type   = SRV_PKT_AUTH_OK;
	srv_pkt->length = htons(data_len);

	send_len = SRV_PKT_MIN_L + data_len;
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static bool send_auth_reject(struct srv_tcp_client *client)
{
	size_t send_len;
	struct srv_tcp_pkt *srv_pkt = client->send_buf.__pkt_chk;

	srv_pkt->type   = SRV_PKT_AUTH_REJECT;
	srv_pkt->length = 0;

	send_len = SRV_PKT_MIN_L;
	return send_to_client(client, srv_pkt, send_len) > 0;
}


static void auth_ok_notice(struct iface_cfg *iface,
			   struct srv_tcp_client *client)
{
	prl_notice(0, "Authentication success from " PRWIU, W_IU(client));
	prl_notice(0, "Assign IP %s %s to " PRWIU, iface->ipv4,
		   iface->ipv4_netmask, W_IU(client));
}


static evt_cli_goto handle_auth(struct srv_tcp_client *client,
				struct srv_tcp_state *state,
				uint16_t data_len)
{
	struct auth_pkt *auth;
	struct iface_cfg *iface;
	struct cli_tcp_pkt *cli_pkt;
	struct srv_tcp_pkt *srv_pkt;
	struct srv_auth_ok *auth_ok;

	cli_pkt   = client->recv_buf.__pkt_chk;
	srv_pkt   = client->send_buf.__pkt_chk;
	auth      = &cli_pkt->auth;
	auth_ok   = &srv_pkt->auth_ok;
	iface     = &auth_ok->iface;

	if (unlikely(data_len < sizeof(struct auth_pkt))) {
		prl_notice(0, "Invalid auth packet from " PRWIU, W_IU(client));
		goto out_fail;
	}

	auth->username[0xffu - 1u] = '\0';
	auth->password[0xffu - 1u] = '\0';

	strncpy(client->username, auth->username, 0xffu - 1u);
	prl_notice(0, "Receive authentication from " PRWIU, W_IU(client));

	if (unlikely(!teavpn_server_get_auth(iface, auth, state->cfg))) {
		prl_notice(0, "Authentication failure from " PRWIU,
			   W_IU(client));
		goto out_fail;
	}

	strncpy(iface->def_gateway, state->cfg->iface.ipv4, IPV4LEN - 1);

	if (unlikely(!send_auth_ok(client))) {
		prl_notice(0, "Authentication error from " PRWIU, W_IU(client));
		goto out_fail;
	}

	auth_ok_notice(iface, client);
	client->is_auth  = true;
	client->on_idx_i = add_online_cl_idx(state, client->arr_idx);
	return RETURN_OK;
out_fail:
	send_auth_reject(client);
	return OUT_CONN_CLOSE;
}


static evt_cli_goto handle_iface_ack(struct srv_tcp_client *client)
{
	client->iface_acked = true;
	return RETURN_OK;
}


static void broadcast_iface_pkt()
{

}


static ssize_t handle_iface_read(int tun_fd, struct srv_tcp_state *state)
{
	int err;
	size_t send_len;
	ssize_t read_ret;
	uint16_t on_idx_n;
	uint16_t *on_idx_arr;
	struct srv_tcp_pkt *srv_pkt = state->srv_pkt.__pkt_chk;
	char *buf = srv_pkt->raw_data;
	struct srv_tcp_client *clients;

	state->read_c++;

	read_ret = read(tun_fd, buf, 4096);
	if (unlikely(read_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return 0;

		state->stop = true;
		pr_error("read(fd=%d) from tun_fd: " PRERR, tun_fd, PREAG(err));
		return -1;
	}

	send_len        = SRV_PKT_MIN_L + (uint16_t)read_ret;
	srv_pkt->type   = SRV_PKT_IFACE_DATA;
	srv_pkt->length = htons((uint16_t)read_ret);
	prl_notice(5, "[%10" PRIu32 "] read(fd=%d) %ld bytes from tun_fd",
		   state->read_c, tun_fd, read_ret);

	on_idx_n   = state->on_idx_n;
	on_idx_arr = state->on_idx_arr;
	clients    = state->clients;

#if 0
	prl_notice(5, "Broadcasting data to %d fds", on_idx_n);
#endif
	broadcast_iface_pkt(state);
	for (uint16_t i = 0; likely(i < on_idx_n); i++) {
		struct srv_tcp_client *client = &clients[on_idx_arr[i]];
		send_to_client(client, srv_pkt, send_len);
	}

	return read_ret;
}


static evt_cli_goto handle_iface_write(struct srv_tcp_client *client,
				       struct srv_tcp_state *state,
				       uint16_t data_len)
{
	int err;
	ssize_t write_ret;
	int tun_fd = state->tun_fd;
	struct cli_tcp_pkt *cli_pkt = client->recv_buf.__pkt_chk;

	if (unlikely(!client->iface_acked))
		return OUT_CONN_CLOSE;

	state->write_c++;
	write_ret = write(tun_fd, cli_pkt->raw_data, data_len);
	if (unlikely(write_ret < 0)) {
		err = errno;
		state->stop = true;
		pr_error("write(fd=%d) to tun_fd: " PRERR, tun_fd, PREAG(err));
		return OUT_CONN_CLOSE;
	}
	prl_notice(5, "[%10" PRIu32 "] write(fd=%d) %ld bytes to tun_fd",
		   state->write_c, tun_fd, write_ret);

	return RETURN_OK;
}


static evt_cli_goto process_client_buf(size_t recv_s,
				       struct srv_tcp_client *client,
				       struct srv_tcp_state *state)
{
	uint16_t pad_n;
	uint16_t data_len;
	uint16_t fdata_len; /* Full data length                        */
	uint16_t cdata_len; /* Current received data length + plus pad */
	evt_cli_goto retval = RETURN_OK;

	char *recv_buf = client->recv_buf.raw;
	struct cli_tcp_pkt *cli_pkt = client->recv_buf.__pkt_chk;

again:
	if (unlikely(recv_s < CLI_PKT_MIN_L)) {
		/*
		 * We haven't received the type and length of packet.
		 * It very unlikely happens, maybe connection is too
		 * slow or the extra data after memmove (?)
		 */
		goto out;
	}

	pad_n     = cli_pkt->pad_n;
	data_len  = ntohs(cli_pkt->length);
	fdata_len = data_len + pad_n;
	if (unlikely(data_len > CLI_PKT_DATA_L)) {
		/*
		 * data_len must never be greater than CLI_PKT_DATA_L.
		 * Is it corrupted packet?
		 */
		prl_notice(0, "Client " PRWIU " sends invalid packet length "
			      "(max_allowed_len = %zu; srv_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", W_IU(client),
			      CLI_PKT_DATA_L, fdata_len, recv_s);

		return client->is_auth ? OUT_CONN_ERR : OUT_CONN_CLOSE;
	}

	/* Calculate current received data length */
	cdata_len = recv_s - CLI_PKT_MIN_L;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We've received the type and length of packet.
		 *
		 * However, the packet has not been fully received.
		 * So let's wait for the next cycle to process it.
		 */
		goto out;
	}

#if 0
	prl_notice(5, "==== Process the packet (type: %d) " PRWIU, cli_pkt->type,
		   W_IU(client));
#endif

	switch (cli_pkt->type) {
	case CLI_PKT_HELLO:
		retval = handle_hello(client);
		break;
	case CLI_PKT_AUTH:
		retval = handle_auth(client, state, data_len);
		break;
	case CLI_PKT_IFACE_ACK:
		retval = handle_iface_ack(client);
		break;
	case CLI_PKT_IFACE_FAIL:
		return OUT_CONN_CLOSE;
	case CLI_PKT_IFACE_DATA:
		retval = handle_iface_write(client, state, data_len);
		break;
	case CLI_PKT_REQSYNC:
		break;
	case CLI_PKT_CLOSE:
		return OUT_CONN_CLOSE;
	default:
		/*
		 * TODO: Change the state to CT_NOSYNC and
		 *       create a recovery rountine.
		 */
		prl_notice(0, "Received invalid packet from " PRWIU
			      " (type: %d)", W_IU(client), cli_pkt->type);

		if (likely(!client->is_auth))
			return OUT_CONN_CLOSE;

		return OUT_CONN_ERR;
	}

	if (unlikely(retval != RETURN_OK))
		return retval;

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra packet on the tail, must memmove to
		 * the head before we run out of buffer.
		 */
		size_t cur_valid_size = CLI_PKT_MIN_L + fdata_len;
		recv_s -= cur_valid_size;

		memmove(recv_buf, recv_buf + cur_valid_size, recv_s);
		prl_notice(5, "memmove " PRWIU " (copy_size: %zu; "
			      "recv_s: %zu; cur_valid_size: %zu)",
			      W_IU(client), recv_s, recv_s, cur_valid_size);

		goto again;
	}
	recv_s = 0;
out:
	client->recv_s = recv_s;
	return RETURN_OK;
}


static void handle_recv_client(int cli_fd, int map, struct srv_tcp_state *state)
{
	int err;
	char *recv_buf;
	size_t recv_s;
	size_t recv_len;
	ssize_t recv_ret;
	int32_t on_idx_i;
	struct srv_tcp_client *client = &state->clients[map];

	client->recv_c++;
	recv_s   = client->recv_s;
	recv_buf = client->recv_buf.raw;
	recv_len = CLI_PKT_RECV_L - recv_s;

	recv_ret = recv(cli_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("recv(fd=%d): " PRERR " " PRWIU, cli_fd, PREAG(err),
			 W_IU(client));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, PRWIU " has closed its connection", W_IU(client));
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "[%10" PRIu32 "] recv(fd=%d) %ld bytes from " PRWIU " "
		   "(recv_s = %zu)", client->recv_c, cli_fd, recv_ret,
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

	if (client->err_c++ < MAX_ERR_C)
		return;

	prl_notice(0, "Connection " PRWIU " reached the max number of error",
		   W_IU(client));
out_close_conn:
	on_idx_i = client->on_idx_i;

	epoll_delete(state->epl_fd, cli_fd);
	close(cli_fd);
	push_cl(&state->cl_stk, client->arr_idx);
	tcp_client_init(client, client->arr_idx);

	if (likely(on_idx_i != -1))
		remove_online_cl_idx(state, on_idx_i);

	state->fds_map[cli_fd] = FDS_MAP_NOOP;
	prl_notice(0, "Closing connection fd from " PRWIU, W_IU(client));
}


static int handle_event(struct srv_tcp_state *state, struct epoll_event *event)
{
	int fd;
	bool is_err;
	uint16_t map;
	uint32_t revents;
	uint16_t *fds_map;
	const uint32_t errev = EPOLLERR | EPOLLHUP;

	fd      = event->data.fd;
	revents = event->events;
	is_err  = ((revents & errev) != 0);
	fds_map = state->fds_map;
	map     = fds_map[fd];

	switch (map) {
	case FDS_MAP_NOOP:
		pr_error("Got FDS_MAP_NOOP from handle_event");
		return -1;
	case FDS_MAP_TUN:
		if (unlikely(is_err)) {
			pr_error("FDS_MAP_TUN error");
			return -1;
		}
		handle_iface_read(fd, state);
		break;
	case FDS_MAP_NET:
		if (unlikely(is_err)) {
			pr_error("FDS_MAP_NET error");
			return -1;
		}
		accept_new_conn(fd, state);
		break;
	default:
		if (likely((revents & EPOLL_INEVT) != 0))
			handle_recv_client(fd, map - FDS_ADD_NUM, state);

		// if (unlikely((revents & EPOLLOUT) != 0)) {
		// 	/* TODO: Handle send() */
		// }
		break;
	}

	return 0;
}


static int event_loop(struct srv_tcp_state *state)
{
	int err;
	int epl_ret;
	int retval = 0;
	int maxevents = 32;
	int epl_fd = state->epl_fd;
	struct epoll_event events[32];

	while (likely(!state->stop)) {
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
				continue;
			}

			retval = -err;
			pr_error("epoll_wait(): " PRERR, PREAG(err));
			break;
		}

		for (int i = 0; likely(i < epl_ret); i++) {
			retval = handle_event(state, &events[i]);
			if (retval < 0)
				goto out;
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
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(net_fd != -1)) {
		prl_notice(0, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	if (likely(epl_fd != -1)) {
		prl_notice(0, "Closing state->epl_fd (%d)", epl_fd);
		close(epl_fd);
	}


	if (unlikely(clients != NULL)) {
		while (likely(max_conn--)) {

			client = clients + max_conn;
			if (unlikely(!client->is_used))
				continue;
			
			prl_notice(6, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);
		}
	}

	free(clients);
	free(state->on_idx_arr);
	free(state->fds_map);
	free(state->cl_stk.arr);
	state->clients = NULL;
	state->on_idx_arr = NULL;
	state->fds_map = NULL;
	state->cl_stk.arr = NULL;
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
	signal(SIGPIPE, SIG_IGN);
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

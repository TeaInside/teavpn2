
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/server/tcp.h>
#include <teavpn2/net/tcp_pkt.h>


#define MAX_ERR_C	(0xfu)
#define EPT_MAP_SIZE	(0xffffu)
#define EPT_MAP_NOP	(0xffffu)	/* Unused map (nop = no operation for index) */
#define EPT_MAP_TO_TUN	(0x0u)
#define EPT_MAP_TO_NET	(0x1u)
#define EPT_MAP_ADD	(0x2u)
#define EPOLL_IN_EVT	(EPOLLIN | EPOLLPRI)

/* Macros for printing */
#define W_IP(CL) ((CL)->src_ip), ((CL)->src_port)
#define W_UN(CL) ((CL)->uname)
#define W_IU(CL) W_IP(CL), W_UN(CL)
#define PRWIU "%s:%d (%s)"

#define IPM_ADD		(0x1u)
#define IPM_MAP_NOP	(0x0u)

typedef enum _evt_cli_goto {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_cli_goto;


struct tcp_client {
	int			cli_fd;		/* Client TCP file descriptor */
	uint32_t		recv_c;		/* sys_recv counter           */
	uint32_t		send_c;		/* sys_send counter           */
	uint16_t		sidx;		/* Client slot index          */
	char			uname[64];	/* Client username            */
	bool			is_auth;	/* Is authenticated?          */
	bool			is_used;	/* Is used?                   */
	bool			is_conn;	/* Is connected?              */
	uint8_t			err_c;		/* Error counter              */
	char			src_ip[IPV4_L];	/* Source IP                  */
	uint16_t		src_port;	/* Source port                */
	struct_pad(0, 4);
	size_t			recv_s;		/* Active bytes in recv_buf   */
	utcli_pkt		recv_buf;
};


struct _cl_stk {
	/*
	 * Stack to retrieve client slot in O(1) time complexity
	 */
	uint16_t		sp;		/* Stack pointer              */
	uint16_t		max_sp;		/* Max stack pointer          */
	struct_pad(0, 4);
	uint16_t		*arr;		/* The array container        */
};


struct _bc_arr {
	/*
	 * Broadcast array
	 */
	uint16_t		n;
	struct_pad(0, 6);
	/* Contains indexes map to client slots */
	uint16_t		*arr;
};


struct srv_tcp_state {
	pid_t			pid;		/* Main process PID           */
	int			epl_fd;		/* Epoll fd                   */
	int			net_fd;		/* Main TCP socket fd         */
	int			tun_fd;		/* TUN/TAP fd                 */
	struct _cl_stk		cl_stk;		/* Stack for slot resolution  */
	uint16_t		*epl_map;	/* Epoll map to client slot   */
	uint16_t		(*ipm)[256];	/* IP addr map to client slot */
	struct tcp_client	*clients;	/* Client slot                */
	struct srv_cfg		*cfg;		/* Config                     */
	uint32_t		read_c;		/* Number of read()           */
	utsrv_pkt		send_buf;	/* Server packet to send()    */
	bool			stop;		/* Stop the event loop?       */
	struct_pad(0, 3);
	struct _bc_arr		br_arr;		/* Broadcast array            */
};


static struct srv_tcp_state *g_state;


static void interrupt_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int32_t push_cl(struct _cl_stk *cl_stk, uint16_t val)
{
	uint16_t sp = cl_stk->sp;

	TASSERT(sp > 0);
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
	TASSERT(sp <= max_sp);

	if (unlikely(sp == max_sp)) {
		/* There is nothing on the stack */
		return -1;
	}

	val = (int32_t)cl_stk->arr[sp];
	cl_stk->sp = ++sp;
	return (int32_t)val;
}


static void tcp_client_init(struct tcp_client *client, uint16_t sidx)
{
	client->cli_fd   = -1;
	client->recv_c   = 0;
	client->send_c   = 0;
	client->uname[0] = '_';
	client->uname[1] = '\0';
	client->sidx     = sidx;
	client->is_used  = false;
	client->is_auth  = false;
	client->is_conn  = false;
	client->err_c    = 0;
	client->recv_s   = 0;
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	uint16_t max_conn;
	struct _cl_stk *cl_stk;
	uint16_t *epl_map = NULL;
	uint16_t *stack_arr = NULL;
	struct tcp_client *clients = NULL;
	uint16_t (*ipm)[256] = NULL;

	max_conn = state->cfg->sock.max_conn;

	clients = calloc(max_conn, sizeof(struct tcp_client));
	if (unlikely(clients == NULL))
		goto out_err;

	stack_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(stack_arr == NULL))
		goto out_err;

	epl_map = calloc(EPT_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(epl_map == NULL))
		goto out_err;

	ipm = calloc(256u, sizeof(uint16_t [256u]));
	if (unlikely(ipm == NULL))
		goto out_err;

	cl_stk         = &state->cl_stk;
	cl_stk->sp     = max_conn; /* Stack growsdown, so start from high idx */
	cl_stk->max_sp = max_conn;
	cl_stk->arr    = stack_arr;

	for (uint16_t i = 0; i < max_conn; i++)
		tcp_client_init(clients + i, i);

	for (uint16_t i = 0; i < EPT_MAP_SIZE; i++)
		epl_map[i] = EPT_MAP_NOP;

	for (uint16_t i = max_conn; i--;)
		push_cl(&state->cl_stk, i);

	for (uint16_t i = 0; i < 256u; i++) {
		for (uint16_t j = 0; j < 256u; j++) {
			ipm[i][j] = IPM_MAP_NOP;
		}
	}

	state->epl_fd    = -1;
	state->net_fd    = -1;
	state->tun_fd    = -1;
	state->stop      = false;
	state->epl_map   = epl_map;
	state->ipm       = ipm;
	state->clients   = clients;
	state->pid       = getpid();

	prl_notice(0, "My PID is %d", state->pid);

	return 0;

out_err:
	err = errno;
	free(clients);
	free(stack_arr);
	free(epl_map);
	pr_err("calloc: Cannot allocate memory: " PRERF, PREAR(err));
	return -ENOMEM;
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

	y = 30000;
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
	pr_err("setsockopt(): " PRERF, PREAR(err));
	return rv;
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
	int net_fd = state->net_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create((int)state->cfg->sock.max_conn + 3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	state->epl_map[tun_fd] = EPT_MAP_TO_TUN;
	ret = epoll_add(epl_fd, tun_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epl_map[net_fd] = EPT_MAP_TO_NET;
	ret = epoll_add(epl_fd, net_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epl_fd = epl_fd;
	return 0;

out_create_err:
	err = errno;
	pr_err("epoll_create(): " PRERF, PREAR(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return -1;
}


static ssize_t handle_iface_read(int tun_fd, struct srv_tcp_state *state)
{
	int err;
	ssize_t read_ret;
	tsrv_pkt *srv_pkt = state->send_buf.__pkt_chk;

	state->read_c++;

	read_ret = read(tun_fd, srv_pkt->raw_data, 4096);
	if (unlikely(read_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return 0;

		pr_err("read(fd=%d /* tun_fd */)" PRERF, tun_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] read(fd=%d) %ld bytes from tun_fd",
		   state->read_c, tun_fd, read_ret);

	/*
	 * TODO: Broadcast the packet to corresponding client(s)
	 */

	return read_ret;
}


static bool resolve_new_conn(int cli_fd, struct sockaddr_in *addr,
			     struct srv_tcp_state *state)
{
	int err;
	uint16_t idx;
	uint16_t sport;
	int32_t ret_idx;
	char buf[IPV4_L + 1];
	struct tcp_client *client;
	uint32_t saddr = addr->sin_addr.s_addr;

	const char *sip;

	/* Get readable source IP address */
	sip = inet_ntop(AF_INET, &addr->sin_addr, buf, IPV4_L);
	if (unlikely(sip == NULL)) {
		err = errno;
		err = err ? err : EINVAL;
		pr_err("inet_ntop(%u): " PRERF, saddr, PREAR(err));
		return false;
	}

	/* Get readable source port */
	sport = ntohs(addr->sin_port);

	ret_idx = pop_cl(&state->cl_stk);
	if (unlikely(ret_idx == -1)) {
		prl_notice(0, "Client slot is full, can't accept connection");
		prl_notice(0, "Dropping connection from %s:%u", sip, sport);
		return false;
	}


	/*
	 * Welcome new connection.
	 * We have an available slot for this new client.
	 */
	idx = (uint16_t)ret_idx;
	err = epoll_add(state->epl_fd, cli_fd, EPOLL_IN_EVT);
	if (unlikely(err < 0)) {
		pr_err("Cannot accept new connection from %s:%u because of "
		       "error on epoll_add()", sip, sport);
		return false;
	}


	/*
	 * state->epl_map[cli_fd] must not be in use
	 */
	TASSERT(state->epl_map[cli_fd] == EPT_MAP_NOP);


	/*
	 * Map the FD to translate to idx later
	 */
	state->epl_map[cli_fd] = idx + EPT_MAP_ADD;


	client = &state->clients[idx];

	client->is_used  = true;
	client->is_conn  = true;
	client->cli_fd   = cli_fd;
	client->src_port = sport;

	strncpy(client->src_ip, sip, IPV4_L - 1);
	client->src_ip[IPV4_L - 1] = '\0';

	TASSERT(client->sidx == idx);

	prl_notice(0, "New connection from " PRWIU " (fd:%d)", W_IU(client),
		   cli_fd);

	return true;
}


static void accept_new_conn(int net_fd, struct srv_tcp_state *state)
{
	int err;
	int cli_fd;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(&addr, 0, addrlen);
	cli_fd = accept(net_fd, (void *)&addr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;

		pr_err("accept: " PRERF, PREAR(err));
		return;
	}

	if (unlikely(!resolve_new_conn(cli_fd, &addr, state)))
		close(cli_fd);
}


static ssize_t send_to_client(struct tcp_client *client,
			      struct srv_tcp_state *state,
			      size_t len)
{
	int err;
	int cli_fd = client->cli_fd;
	ssize_t send_ret;
	tsrv_pkt *srv_pkt = state->send_buf.__pkt_chk;

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

		pr_err("send(fd=%d)" PRERF, cli_fd, PREAR(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %ld bytes to " PRWIU,
		   client->send_c, cli_fd, send_ret, W_IU(client));

	return send_ret;
}


static bool send_close(struct tcp_client *client, struct srv_tcp_state *state)
{
	size_t send_len;
	tsrv_pkt *srv_pkt = state->send_buf.__pkt_chk;

	srv_pkt->type   = TSRV_PKT_CLOSE;
	srv_pkt->npad   = 0;
	srv_pkt->length = 0;
	send_len        = TSRV_PKT_MIN_L;

	return send_to_client(client, state, send_len) > 0;
}


static bool send_welcome(struct tcp_client *client, struct srv_tcp_state *state)
{
	size_t send_len;
	tsrv_pkt *srv_pkt = state->send_buf.__pkt_chk;

	srv_pkt->type   = TSRV_PKT_WELCOME;
	srv_pkt->npad   = 0;
	srv_pkt->length = 0;
	send_len        = TSRV_PKT_MIN_L;

	return send_to_client(client, state, send_len) > 0;
}


static evt_cli_goto handle_hello(struct tcp_client *client,
				 struct srv_tcp_state *state,
				 uint16_t data_len)
{
	tcli_pkt *cli_pkt;
	struct tcli_hello_pkt *hlo_pkt;
	version_t cmp_ver = {
		.ver       = VERSION,
		.patch_lvl = PATCHLEVEL,
		.sub_lvl   = SUBLEVEL,
		.extra     = EXTRAVERSION
	};


	/* Ignore auth packet from authenticated client */
	if (unlikely(client->is_auth))
		return RETURN_OK;

	/* Wrong data length */
	if (data_len != sizeof(cmp_ver)) {
		prl_notice(0, "Client " PRWIU " sends invalid hello data "
			   "length (expected: %zu; got: %u)", W_IU(client),
			   sizeof(cmp_ver), data_len);
		return OUT_CONN_CLOSE;
	}

	cli_pkt = client->recv_buf.__pkt_chk;
	hlo_pkt = &cli_pkt->hello_pkt;

	if (memcmp(&hlo_pkt->v, &cmp_ver, sizeof(cmp_ver)) != 0) {

		/* For safe print, in case client sends non null-terminated */
		hlo_pkt->v.extra[sizeof(hlo_pkt->v.extra) - 1] = '\0';

		pr_err("Invalid client version from " PRWIU
		       "(got: %u.%u.%u%s; expected: %u.%u.%u%s)",
		       W_IU(client),
		       hlo_pkt->v.ver,
		       hlo_pkt->v.patch_lvl,
		       hlo_pkt->v.sub_lvl,
		       hlo_pkt->v.extra,
		       cmp_ver.ver,
		       cmp_ver.patch_lvl,
		       cmp_ver.sub_lvl,
		       cmp_ver.extra);


		send_close(client, state);

		return OUT_CONN_CLOSE;
	}

	return (send_welcome(client, state) > 0) ? RETURN_OK : OUT_CONN_CLOSE;
}


static evt_cli_goto handle_client_pkt(tcli_pkt *cli_pkt,
				      struct tcp_client *client,
				      uint16_t data_len,
				      struct srv_tcp_state *state)
{
	(void)client;
	(void)state;
	(void)data_len;
	(void)IPM_ADD;
	evt_cli_goto retval = RETURN_OK;

	switch (cli_pkt->type) {
	case TCLI_PKT_HELLO:
		retval = handle_hello(client, state, data_len);
		goto out;
	case TCLI_PKT_AUTH:
		goto out;
	case TCLI_PKT_IFACA_ACK:
		goto out;
	case TCLI_PKT_IFACE_DATA:
		goto out;
	case TCLI_PKT_REQSYNC:
		goto out;
	case TCLI_PKT_PING:
		goto out;
	case TCLI_PKT_CLOSE:
		goto out;
	}

	/*
	 * I don't put default on switch statement to shut
	 * the clang warning up!
	 */

	/* default: */
	/*
	 * TODO: Change the state to CT_NOSYNC and
	 *       create a recovery rountine.
	 */

	if ((NOTICE_MAX_LEVEL) >= 5) {
		/*
		 * Something is wrong!
		 *
		 * Let's debug this by hand by seeing the
		 * hexdump result.
		 */
		VT_HEXDUMP(cli_pkt, sizeof(*cli_pkt));
		panic("CORRUPTED PACKET!");
	}

	prl_notice(0, "Received invalid packet type from " PRWIU " (type: %d)",
		   W_IU(client), cli_pkt->type);

	if (likely(!client->is_auth))
		return OUT_CONN_CLOSE;

	return OUT_CONN_ERR;

out:
	return retval;
}


static evt_cli_goto process_client_buf(size_t recv_s, struct tcp_client *client,
				       struct srv_tcp_state *state)
{
	uint16_t npad;
	uint16_t data_len;
	uint16_t fdata_len; /* Full data length                        */
	uint16_t cdata_len; /* Current received data length + plus pad */
	evt_cli_goto retval;

	tcli_pkt *cli_pkt = client->recv_buf.__pkt_chk;
	char *recv_buf = client->recv_buf.raw_buf;

process_again:
	if (unlikely(recv_s < TCLI_PKT_MIN_L)) {
		/*
		 * We can't continue to process the packet at this point,
		 * because we have not received the `type of packet` and
		 * the `length of packet`.
		 *
		 * Kick out!
		 * Let's wait for the next cycle.
		 */
		goto out;
	}

	npad      = cli_pkt->npad;
	data_len  = ntohs(cli_pkt->length);
	fdata_len = data_len + npad;
	if (unlikely(data_len > TCLI_PKT_MAX_L)) {


		if ((NOTICE_MAX_LEVEL) >= 5) {
			/*
			 * Something is wrong!
			 *
			 * Let's debug this by hand by seeing the
			 * hexdump result.
			 */
			VT_HEXDUMP(cli_pkt, sizeof(*cli_pkt));
			panic("CORRUPTED PACKET!");
		}


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

		/*
		 * If the client has been authenticated, let's give them
		 * a chance for the next several cycles until `client->err_c`
		 * reaches the max number of its allowed value.
		 *
		 * So we only **directly drop** unauthenticated client :)
		 */
		return (
			client->is_auth ?

			/* Add error counter */
			OUT_CONN_ERR :

			/* Drop the connection */
			OUT_CONN_CLOSE
		);
	}


	/* Calculate current received data length */
	cdata_len = (uint16_t)recv_s - (uint16_t)TCLI_PKT_MIN_L;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * **We really have received** the type and length of packet.
		 *
		 * However, the packet has not been fully received.
		 * So let's wait for the next cycle to process it.
		 */
		goto out;
	}

	retval = handle_client_pkt(cli_pkt, client, data_len, state);
	if (unlikely(retval != RETURN_OK))
		return retval;

	if (likely(cdata_len > fdata_len)) {
		/*
		 * We have extra packet on the tail, must memmove to
		 * the head before we run out of buffer.
		 */
		size_t cur_valid_size = TCLI_PKT_MIN_L + fdata_len;
		recv_s -= cur_valid_size;

		memmove(recv_buf, recv_buf + cur_valid_size, recv_s);

		prl_notice(5, "memmove " PRWIU " (copy_size: %zu; "
			      "recv_s: %zu; cur_valid_size: %zu)",
			      W_IU(client), recv_s, recv_s, cur_valid_size);

		goto process_again;
	}

	recv_s = 0;
out:
	client->recv_s = recv_s;
	return RETURN_OK;
}


static void handle_recv_client(int cli_fd, uint16_t map_to,
			       struct srv_tcp_state *state)
{
	int err;
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	ssize_t recv_ret;
	struct tcp_client *client;

	client   = &state->clients[map_to];
	recv_s   = client->recv_s;
	recv_len = TCLI_PKT_RECV_L - recv_s;
	recv_buf = client->recv_buf.raw_buf;

	recv_ret = recv(cli_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_err("recv(fd=%d): " PRERF " " PRWIU, cli_fd, PREAR(err),
		       W_IU(client));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, PRWIU " has closed its connection", W_IU(client));
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "recv(fd=%d) %ld bytes from " PRWIU " (recv_s = %zu)",
		   cli_fd, recv_ret, W_IU(client), recv_s);

	switch (process_client_buf(recv_s, client, state)) {
	case RETURN_OK:
		return;
	case OUT_CONN_ERR:
		goto out_err_c;
	case OUT_CONN_CLOSE:
		goto out_close_conn;
	}

	return;

out_err_c:
	client->recv_s = 0;

	if (client->err_c++ < MAX_ERR_C)
		return;

	prl_notice(0, "Connection " PRWIU " reached the max number of error",
		   W_IU(client));

out_close_conn:
	epoll_delete(state->epl_fd, cli_fd);
	close(cli_fd);

	/* Restore the slot into the stack */
	push_cl(&state->cl_stk, client->sidx);

	/* Reset client state */
	tcp_client_init(client, client->sidx);

	state->epl_map[cli_fd] = EPT_MAP_NOP;
	prl_notice(0, "Closing connection fd from " PRWIU, W_IU(client));
}


static int handle_event(struct srv_tcp_state *state, struct epoll_event *event)
{
	int fd;
	bool is_err;
	uint16_t map_to;
	uint32_t revents;
	uint16_t *epl_map = state->epl_map;
	const uint32_t errev = EPOLLERR | EPOLLHUP;
	const uint32_t inev  = EPOLL_IN_EVT;
	const uint32_t outev = EPOLLOUT;

	fd      = event->data.fd;
	revents = event->events;
	is_err  = ((revents & errev) != 0);
	map_to  = epl_map[fd];

	switch (map_to) {
	case EPT_MAP_TO_TUN:
		if (unlikely(is_err)) {
			pr_err("tun_fd wait error");
			return -1;
		}
		if (unlikely(handle_iface_read(fd, state) < 0))
			return -1;
		break;
	case EPT_MAP_TO_NET:
		if (unlikely(is_err)) {
			pr_err("net_fd wait error");
			return -1;
		}
		accept_new_conn(fd, state);
		break;
	default:
		map_to -= EPT_MAP_ADD;
		if (likely((revents & inev) != 0))
			handle_recv_client(fd, map_to, state);

		if (unlikely((revents & outev) != 0)) {
			/* TODO: Handle send() */
		}
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
			pr_error("epoll_wait(): " PRERF, PREAR(err));
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
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = state->cfg->sock.max_conn;

	prl_notice(0, "Cleaning state...");
	state->stop = true;

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
			struct tcp_client *client = clients + max_conn;

			if (unlikely(!client->is_used))
				goto clear;
			
			prl_notice(0, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);

		clear:
			memset(client, 0, sizeof(struct tcp_client));
		}
	}

	free(state->ipm);
	free(state->clients);
	free(state->epl_map);
	free(state->cl_stk.arr);

	state->ipm = NULL;
	state->clients = NULL;
	state->epl_map = NULL;
	state->cl_stk.arr = NULL;
	prl_notice(0, "Cleaned up!");
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, interrupt_handler);
	signal(SIGINT, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGQUIT, interrupt_handler);
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

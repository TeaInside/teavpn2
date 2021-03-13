
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
#include <teavpn2/client/tcp.h>
#include <teavpn2/net/tcp_pkt.h>



#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)


struct cli_tcp_state {
	int			epoll_fd;
	int			tcp_fd;
	int			tun_fd;

	struct_pad(0, 4);
	struct cli_cfg		*cfg;

	uint32_t		recv_c;
	uint32_t		send_c;
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	utcli_pkt_t		send_buf;
	tsrv_pkt_t		recv_buf;

	bool			stop;
	struct_pad(1, 3);
};


static struct cli_tcp_state *g_state;


static void handle_interrupt(int sig)
{
	struct cli_tcp_state *state = g_state;
	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int init_state(struct cli_tcp_state *state)
{

	state->epoll_fd     = -1;
	state->tcp_fd       = -1;
	state->tun_fd       = -1;
	state->stop         = false;
	state->send_c       = 0;
	state->recv_c       = 0;
	state->read_tun_c   = 0;
	state->write_tun_c  = 0;

	return 0;
}


static int init_iface(struct cli_tcp_state *state)
{
	int fd;
	struct cli_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	fd = tun_alloc(j->dev, IFF_TUN | IFF_NO_PI);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	state->tun_fd = fd;
	return 0;
out_err:
	close(fd);
	return -1;
}


static int socket_setup(int fd, struct cli_cfg *cfg)
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


static int init_socket(struct cli_tcp_state *state)
{
	int fd;
	int err;
	int retval;
	struct sockaddr_in addr;
	struct cli_sock_cfg *sock = &state->cfg->sock;
	char *server_addr = sock->server_addr;
	uint16_t server_port = sock->server_port;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	prl_notice(0, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		err = errno;
		retval = -err;
		pr_error("socket(): " PRERF, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (unlikely(retval < 0))
		goto out_err;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	if (!inet_pton(AF_INET, server_addr, &addr.sin_addr)) {
		err = EINVAL;
		retval = -err;
		pr_error("inet_pton(%s): " PRERF, server_addr, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Connecting to %s:%d...", server_addr, server_port);

again:
	retval = connect(fd, (void *)&addr, addrlen);
	if (retval < 0) {
		err = errno;
		if ((err == EINPROGRESS) || (err == EALREADY)) {
			usleep(5000);
			goto again;
		}

		retval = -err;
		pr_error("connect(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = fd;
	prl_notice(0, "Connection established!");

	return 0;
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


static int init_epoll(struct cli_tcp_state *state)
{
	int err;
	int ret;
	int epl_fd = -1;
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create(3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	ret = epoll_add(epl_fd, tun_fd, EPL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

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


static ssize_t send_to_server(struct cli_tcp_state *state, tcli_pkt_t *cli_pkt,
			      size_t len)
{
	int err;
	size_t usend_ret;
	ssize_t send_ret;
	int tcp_fd = state->tcp_fd;

	state->send_c++;
	send_ret = send(tcp_fd, cli_pkt, len, 0);
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/*
			 * TODO: Handle pending buffer
			 *
			 * For now, let it fallthrough to error.
			 */
			pr_err("Pending buffer detected: EAGAIN");
			return 0;
		}

		pr_err("send(fd=%d)" PRERF, tcp_fd, PREAR(err));
		return -1;
	}

	usend_ret = (size_t)send_ret;
	if (unlikely(len != usend_ret)) {
		/*
		 * TODO: Handle pending buffer
		 */
		pr_err("Pending buffer detected: "
		       "(expected len: %zu; usend_ret: %zu)",
		       len, usend_ret);
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %zd bytes to server",
		   state->send_c, tcp_fd, send_ret);

	return send_ret;
}


static size_t set_cli_pkt_buf(tcli_pkt_t *cli_pkt, tcli_pkt_type type,
				 uint16_t length)
{
	cli_pkt->type   = type;
	cli_pkt->npad   = 0;
	cli_pkt->length = htons(length);

	return TCLI_PKT_MIN_L + length;
}


static void build_hello_packet(struct tcli_hello_pkt *hlo_pkt)
{
	/*
	 * Tell the server what my version is.
	 */
	memset(&hlo_pkt->v, 0, sizeof(hlo_pkt->v));

	hlo_pkt->v.ver       = VERSION;
	hlo_pkt->v.patch_lvl = PATCHLEVEL;
	hlo_pkt->v.sub_lvl   = SUBLEVEL;

	strncpy(hlo_pkt->v.extra, EXTRAVERSION, sizeof(hlo_pkt->v.extra) - 1);
	hlo_pkt->v.extra[sizeof(hlo_pkt->v.extra) - 1] = '\0';
}


static int send_hello(struct cli_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	tcli_pkt_t *cli_pkt;

	prl_notice(2, "Sending hello packet to server...");

	cli_pkt = state->send_buf.__pkt_chk;
	build_hello_packet(&cli_pkt->hello_pkt);

	data_len = sizeof(struct tcli_hello_pkt);
	send_len = set_cli_pkt_buf(cli_pkt, TCLI_PKT_HELLO, data_len);

	if (send_to_server(state, cli_pkt, send_len) > 0)
		return 0;

	return -1;
}


static void close_file_descriptors(struct cli_tcp_state *state)
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


static void destroy_state(struct cli_tcp_state *state)
{
	close_file_descriptors(state);
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval = 0;
	struct cli_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct cli_tcp_state));

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
	retval = send_hello(&state);
	if (unlikely(retval < 0))
		goto out;
out:
	destroy_state(&state);
	return retval;
}

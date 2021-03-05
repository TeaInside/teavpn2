
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <inttypes.h>
#include <stdalign.h>
#include <linux/ip.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/tcp.h>
#include <teavpn2/server/linux/tcp.h>


#define MAX_ERR_C    (15)
#define EPOLL_INEVT  (EPOLLIN | EPOLLPRI)


typedef enum _evt_srv_goto {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_srv_goto;


struct cli_tcp_state {
	int			epl_fd;
	int			tun_fd;
	int			net_fd;
	uint8_t			err_c;
	uint32_t		read_c;
	uint32_t		write_c;
	size_t			recv_s;
	uint32_t		recv_c;
	alignas(16) srv_tcp_pkt_buf		recv_buf;
	uint32_t		send_c;
	alignas(16) cli_tcp_pkt_buf		send_buf;
	bool			stop;
	bool			is_auth;
	struct cli_cfg		*cfg;
};


static struct cli_tcp_state *g_state;


static void intr_handler(int sig)
{
	struct cli_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	prl_notice(0, "Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int init_state(struct cli_tcp_state *state)
{
	int err;
	cpu_set_t affinity;

	state->stop = false;
	state->is_auth = false;
	state->net_fd = -1;
	state->tun_fd = -1;
	state->epl_fd = -1;
	state->send_c = 0;
	state->recv_c = 0;
	state->recv_s = 0;
	state->read_c = 0;
	state->write_c = 0;

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


static int init_iface(struct cli_tcp_state *state)
{
	int fd;
	struct cli_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);
	fd = tun_alloc(j->dev, IFF_TUN);
	if (fd < 0)
		return -1;
	if (fd_set_nonblock(fd) < 0)
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

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 0;
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

	y = 300000;
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
		pr_error("socket(): " PRERR, PREAG(err));
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
		pr_error("inet_pton(%s): " PRERR, server_addr, PREAG(err));
		goto out_err;
	}

	prl_notice(0, "Connecting to %s:%d...", server_addr, server_port);
again:
	retval = connect(fd, &addr, addrlen);
	if (retval < 0) {
		err = errno;
		if ((err == EINPROGRESS) || (err == EALREADY)) {
			usleep(1000);
			goto again;
		}

		retval = -err;
		pr_error("connect(): " PRERR, PREAG(err));
		goto out_err;
	}

	state->net_fd = fd;
	prl_notice(0, "Connection established!");
	return 0;

out_err:
	if (fd > 0)
		close(fd);
	return retval;
}


static int init_epoll(struct cli_tcp_state *state)
{
	int err;
	int epl_fd;
	int retval;

	prl_notice(0, "Initializing epoll fd...");

	epl_fd = epoll_create(3);
	if (unlikely(epl_fd < 0)) {
		err = errno;
		retval = epl_fd;
		pr_error("epoll_create(): " PRERR, PREAG(err));
		goto out_err;
	}

	retval = epoll_add(epl_fd, state->tun_fd, EPOLL_INEVT);
	if (unlikely(retval < 0))
		goto out_err_epctl;

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


static ssize_t send_to_server(struct cli_tcp_state *state,
			      struct cli_tcp_pkt *cli_pkt,
			      size_t send_len)
{
	int err;
	ssize_t send_ret;
	int net_fd = state->net_fd;

	cli_pkt->pad_n = 0;
	send_ret       = send(net_fd, cli_pkt, send_len, 0);
	state->send_c++;
	if (unlikely(send_ret < 0)) {
		err = errno;
		if (err == EAGAIN) {
			/* TODO: Handle pending buffer.
			 *
			 * Let it fallthrough at the moment.
			 */
		}

		state->err_c++;
		pr_error("send(fd=%d) to server: " PRERR, net_fd, PREAG(err));
		return -1;
	}

	prl_notice(5, "[%10" PRIu32 "] send(fd=%d) %ld bytes to server",
		   state->send_c, net_fd, send_ret);
	return send_ret;
}


static bool send_hello(struct cli_tcp_state *state)
{
	size_t send_len;
	struct cli_tcp_pkt *cli_pkt = state->send_buf.__pkt_chk;

	send_len        = CLI_PKT_MIN_L;
	cli_pkt->type   = CLI_PKT_HELLO;
	cli_pkt->length = 0;
	prl_notice(2, "Sending hello packet to server...");
	return send_to_server(state, cli_pkt, send_len) > 0;
}


static ssize_t handle_iface_read(int tun_fd, struct cli_tcp_state *state)
{
	int err;
	size_t send_len;
	ssize_t read_ret;
	struct cli_tcp_pkt *cli_pkt = state->send_buf.__pkt_chk;
	void *buf = cli_pkt->raw_data;
	//struct iphdr *iphdr = (struct iphdr *)((char *)buf + 4);

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

#if 0
	prl_notice(0, "daddr = %x", iphdr->daddr);
	prl_notice(0, "saddr = %x", iphdr->saddr);

	VT_HEXDUMP(buf, (size_t)read_ret);
#endif
	send_len        = CLI_PKT_MIN_L + (uint16_t)read_ret;
	cli_pkt->type   = CLI_PKT_IFACE_DATA;
	cli_pkt->length = htons((uint16_t)read_ret);
	prl_notice(5, "[%10" PRIu32 "] read(fd=%d) %ld bytes from tun_fd",
		   state->read_c, tun_fd, read_ret);

	return send_to_server(state, cli_pkt, send_len) > 0;
}


static bool send_auth(struct cli_tcp_state *state)
{
	size_t send_len;
	uint16_t data_len;
	struct auth_pkt	*auth;
	struct cli_tcp_pkt *cli_pkt;
	struct cli_auth_cfg *auth_cfg;

	cli_pkt  = state->send_buf.__pkt_chk;
	auth     = &cli_pkt->auth;
	auth_cfg = &state->cfg->auth;

	prl_notice(0, "Authenticating as %s...", auth_cfg->username);
	data_len        = sizeof(struct auth_pkt);
	cli_pkt->type   = CLI_PKT_AUTH;
	cli_pkt->length = htons(data_len);

	strncpy(auth->username, auth_cfg->username, 0xffu - 1u);
	strncpy(auth->password, auth_cfg->password, 0xffu - 1u);
	auth->username[0xffu - 1u] = '\0';
	auth->password[0xffu - 1u] = '\0';

	send_len = CLI_PKT_MIN_L + data_len;
	return send_to_server(state, cli_pkt, send_len) > 0;
}


static evt_srv_goto handle_banner(struct srv_tcp_pkt *srv_pkt,
				  struct cli_tcp_state *state)
{
	struct ver_info cmp = {
		.ver = 0,
		.sub_ver = 0,
		.sub_sub_ver = 1
	};
	struct srv_banner *banner = &srv_pkt->banner;

	if (unlikely(state->is_auth))
		return RETURN_OK;

	if (unlikely(memcmp(&banner->cur, &cmp, sizeof(cmp)) != 0)) {
		pr_error("Invalid server banner "
			 "(got: %u.%u.%u; expected: %u.%u.%u)",
			 banner->cur.ver,
			 banner->cur.sub_ver,
			 banner->cur.sub_sub_ver,
			 cmp.ver,
			 cmp.sub_ver,
			 cmp.sub_sub_ver);
		return OUT_CONN_CLOSE;
	}

	if (unlikely(!send_auth(state)))
		return OUT_CONN_CLOSE;

	return RETURN_OK;
}


static bool send_iface_ack(struct cli_tcp_state *state)
{
	struct cli_tcp_pkt *cli_pkt = state->send_buf.__pkt_chk;

	cli_pkt->type   = CLI_PKT_IFACE_ACK;
	cli_pkt->length = 0;

	return send_to_server(state, cli_pkt, CLI_PKT_MIN_L) > 0;
}


static evt_srv_goto handle_auth_ok(struct srv_tcp_pkt *srv_pkt,
				   struct cli_tcp_state *state)
{
	struct cli_cfg *cfg;
	struct iface_cfg *iface;
	struct srv_auth_ok *auth_ok;
	struct cli_iface_cfg *iface_cfg;

	cfg       = state->cfg;
	iface_cfg = &cfg->iface;
	auth_ok   = &srv_pkt->auth_ok;
	iface     = &auth_ok->iface;

	strncpy(iface->dev, iface_cfg->dev, sizeof(iface->dev) - 1);

	if (unlikely(!raise_up_interface(iface))) {
		pr_error("Cannot raise up virtual network interface");
		return OUT_CONN_CLOSE;
	}

	prl_notice(0, "Virtual network interface has been raised up");
	prl_notice(0, "Initialization Sequence Completed");

	if (unlikely(!send_iface_ack(state)))
		return OUT_CONN_CLOSE;

	return RETURN_OK;
}


static evt_srv_goto handle_iface_write(struct cli_tcp_state *state,
				       uint16_t data_len)
{
	int err;
	ssize_t write_ret;
	int tun_fd = state->tun_fd;
	struct srv_tcp_pkt *srv_pkt = state->recv_buf.__pkt_chk;

	state->write_c++;
	write_ret = write(tun_fd, srv_pkt->raw_data, data_len);
	if (unlikely(write_ret < 0)) {
		err = errno;
		pr_error("write(fd=%d) to tun_fd: " PRERR, tun_fd, PREAG(err));
		return OUT_CONN_CLOSE;
	}
	prl_notice(5, "[%10" PRIu32 "] write(fd=%d) %ld bytes to tun_fd",
		   state->write_c, tun_fd, write_ret);

	return RETURN_OK;
}


static evt_srv_goto handle_auth_reject(struct cli_tcp_state *state)
{
	if (unlikely(state->is_auth))
		return RETURN_OK;

	pr_error("Authentication failure");
	return OUT_CONN_CLOSE;
}


static evt_srv_goto process_server_buf(size_t recv_s,
				       struct cli_tcp_state *state)
{
	uint16_t pad_n;
	uint16_t data_len;
	uint16_t fdata_len; /* Full data length                        */
	uint16_t cdata_len; /* Current received data length + plus pad */
	evt_srv_goto retval = RETURN_OK;

	char *recv_buf = state->recv_buf.raw;
	struct srv_tcp_pkt *srv_pkt = state->recv_buf.__pkt_chk;

again:
	if (unlikely(recv_s < SRV_PKT_MIN_L)) {
		/*
		 * We haven't received the type and length of packet.
		 * It very unlikely happens, maybe connection is too
		 * slow or the extra data after memmove (?)
		 */
		goto out;
	}

	pad_n     = srv_pkt->pad_n;
	data_len  = ntohs(srv_pkt->length);
	fdata_len = data_len + pad_n;
	if (unlikely(data_len > SRV_PKT_DATA_L)) {
		/*
		 * data_len must never be greater than SRV_PKT_DATA_L.
		 * Is it corrupted packet?
		 */
		prl_notice(0, "Server sends invalid packet length "
			      "(max_allowed_len = %zu; srv_pkt->length = %u; "
			      "recv_s = %zu) CORRUPTED PACKET?", SRV_PKT_DATA_L,
			      fdata_len, recv_s);

		return state->is_auth ? OUT_CONN_ERR : OUT_CONN_CLOSE;
	}

	/* Calculate current received data length */
	cdata_len = recv_s - SRV_PKT_MIN_L;
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
	prl_notice(5, "==== Process the packet (type: %d)", srv_pkt->type);
#endif

	switch (srv_pkt->type) {
	case SRV_PKT_BANNER:
		retval = handle_banner(srv_pkt, state);
		break;
	case SRV_PKT_AUTH_OK:
		retval = handle_auth_ok(srv_pkt, state);
		break;
	case SRV_PKT_AUTH_REJECT:
		retval = handle_auth_reject(state);
		break;
	case SRV_PKT_IFACE_DATA:
		retval = handle_iface_write(state, data_len);
		break;
	case SRV_PKT_REQSYNC:
		break;
	case SRV_PKT_CLOSE:
		return OUT_CONN_CLOSE;
	default:
		/*
		 * TODO: Change the state to CT_NOSYNC and
		 *       create a recovery rountine.
		 */
		prl_notice(0, "Received invalid packet from server (type: %d)",
			   srv_pkt->type);

		if (likely(!state->is_auth))
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
		prl_notice(5, "memmove (copy_size: %zu; recv_s: %zu; "
			   "cur_valid_size: %zu)", recv_s, recv_s,
			   cur_valid_size);

		goto again;
	}
	recv_s = 0;
out:
	state->recv_s = recv_s;
	return RETURN_OK;
}


static void handle_recv_server(int net_fd, struct cli_tcp_state *state)
{
	int err;
	char *recv_buf;
	size_t recv_s;
	size_t recv_len;
	ssize_t recv_ret;

	recv_s   = state->recv_s;
	recv_buf = state->recv_buf.raw;
	recv_len = CLI_PKT_RECV_L - recv_s;

	state->recv_c++;
	recv_ret = recv(net_fd, recv_buf + recv_s, recv_len, 0);
	if (unlikely(recv_ret < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;
		pr_error("recv(fd=%d): " PRERR, net_fd, PREAG(err));
		goto out_err_c;
	}

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "Server has closed its connection");
		goto out_close_conn;
	}

	recv_s += (size_t)recv_ret;

	prl_notice(5, "[%10" PRIu32 "] recv(fd=%d) %ld from server",
		   state->recv_c, net_fd, recv_ret);

	switch (process_server_buf(recv_s, state)) {
	case RETURN_OK:
		return;
	case OUT_CONN_ERR:
		goto out_err_c;
	case OUT_CONN_CLOSE:
		goto out_close_conn;
	}

out_err_c:
	state->recv_s = 0;
	if (likely(state->err_c++ < MAX_ERR_C))
		return;

	pr_error("Reached the max number of errors, terminating...");
out_close_conn:
	prl_notice(0, "Stopping event loop...");
	state->stop = true;
	return;
}


static int handle_event(struct cli_tcp_state *state, struct epoll_event *event)
{
	int fd;
	bool is_err;
	uint32_t revents;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;
	const uint32_t errev = EPOLLERR | EPOLLHUP;

	fd      = event->data.fd;
	revents = event->events;
	is_err  = ((revents & errev) != 0);

	if (likely(tun_fd == fd)) {
		if (unlikely(is_err)) {
			pr_error("Error tun_fd wait");
			return -1;
		}
		handle_iface_read(tun_fd, state);
		goto out;
	}

	if (likely(net_fd == fd)) {
		if (unlikely(is_err)) {
			int err;
			char buf[8];
			ssize_t ret = recv(fd, buf, 8, 0);

			err = errno;
			pr_error("net_fd wait: (ret: %ld) " PRERR, ret,
				 PREAG(err));
			return -1;
		}
		handle_recv_server(net_fd, state);
		goto out;
	}

out:
	return 0;
}


static int event_loop(struct cli_tcp_state *state)
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
			if (unlikely(retval < 0))
				goto out;
		}
	}
out:
	return retval;
}


static void destroy_state(struct cli_tcp_state *state)
{
	int epl_fd = state->epl_fd;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;

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
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval;
	struct cli_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct cli_tcp_state));

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
	if (retval < 0)
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
	prl_notice(0, "Waiting for server banner...");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

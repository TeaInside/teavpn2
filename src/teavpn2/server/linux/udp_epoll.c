// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
#include <unistd.h>
#include <teavpn2/server/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/udp.h>


static int create_epoll_fd(void)
{
	int ret = 0;
	int epoll_fd;

	epoll_fd = epoll_create(255);
	if (unlikely(epoll_fd < 0)) {
		ret = errno;
		pr_err("epoll_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	return epoll_fd;
}


static int epoll_add(struct epl_thread *thread, int fd, uint32_t events,
		     epoll_data_t data)
{
	int ret;
	struct epoll_event evt;
	int epoll_fd = thread->epoll_fd;

	memset(&evt, 0, sizeof(evt));
	evt.events = events;
	evt.data = data;

	prl_notice(4, "[for thread %u] Adding fd (%d) to epoll_fd (%d)",
		   thread->idx, fd, epoll_fd);


	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &evt);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d, events): " PRERF,
			epoll_fd, fd, PREAR(ret));
		ret = -ret;
	}

	return ret;
}


static int init_epoll_fd_add(struct srv_udp_state *state,
			     struct epl_thread *thread)
{
	int ret;
	epoll_data_t data;
	int *tun_fds = state->tun_fds;
	uint8_t nn = state->cfg->sys.thread_num;
	const uint32_t events = EPOLLIN | EPOLLPRI;

	memset(&data, 0, sizeof(data));

	if (thread->idx == 0) {
		/*
		 * Main thread is responsible to handle data
		 * from UDP socket.
		 */
		data.fd = state->udp_fd;
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (nn == 1) {
			/*
			 * If we are single-threaded, the main thread
			 * is also responsible to read from TUN fd.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	} else {
		data.fd = tun_fds[thread->idx];
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (thread->idx == 1) {
			/*
			 * If we are multithreaded, the subthread is responsible
			 * to read from tun_fds[0]. Don't give this work to the
			 * main thread for better concurrency.
			 */
			data.fd = tun_fds[0];
			ret = epoll_add(thread, data.fd, events, data);
			if (unlikely(ret))
				return ret;
		}
	}

	return 0;
}


static int wait_for_fd_be_writable(int fd, int timeout)
{
	int ret;
	struct pollfd fds[1];
	const nfds_t nfds = 1;

	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;

	ret = poll(fds, nfds, timeout);
	if (ret <= 0) {

		if (ret == 0)
			return -ETIMEDOUT;

		ret = errno;
		if (ret != EINTR)
			pr_err("poll(): " PRERF, PREAR(ret));

		return -ret;
	}

	return 0;
}


static int init_epoll_thread(struct srv_udp_state *state,
			     struct epl_thread *thread)
{
	int ret;

	ret = create_epoll_fd();
	if (unlikely(ret < 0))
		return ret;

	thread->epoll_fd = ret;
	thread->epoll_timeout = EPOLL_TIMEOUT;

	return init_epoll_fd_add(state, thread);
}


static int init_epoll_thread_array(struct srv_udp_state *state)
{
	int ret = 0;
	struct epl_thread *threads;
	uint8_t i, nn = state->cfg->sys.thread_num;

	if (unlikely(nn < 1)) {
		panic("Invalid thread num (%hhu)", nn);
		__builtin_unreachable();
	}

	state->epl_threads = NULL;
	threads = calloc_wrp((size_t)nn, sizeof(*threads));
	if (unlikely(!threads))
		return -errno;

	state->epl_threads = threads;

	/*
	 * Initialize all epoll_fd to -1, in case we fail to
	 * create the epoll instance, the close function will
	 * know which fds need to be closed.
	 *
	 * If the fd is -1, it does not need to be closed.
	 */
	for (i = 0; i < nn; i++) {
		threads[i].idx = i;
		threads[i].state = state;
		threads[i].epoll_fd = -1;
	}

	for (i = 0; i < nn; i++) {
		struct sc_pkt *pkt;

		ret = init_epoll_thread(state, &threads[i]);
		if (unlikely(ret))
			return ret;

		pkt = al4096_malloc_mmap(sizeof(*pkt));
		if (unlikely(!pkt))
			return -errno;

		threads[i].pkt = pkt;
	}

	return 0;
}


static ssize_t _send_to_client(struct srv_udp_state *state,
			       const void *buf, size_t pkt_len,
			       struct sockaddr *dst_addr)
{
	int err;
	ssize_t send_ret;
	int udp_fd = state->udp_fd;
	const socklen_t addr_len = sizeof(struct sockaddr_in);

	if (unlikely(pkt_len == 0))
		return 0;

	send_ret = sendto(udp_fd, buf, pkt_len, 0, dst_addr, addr_len);
	if (unlikely(send_ret <= 0)) {

		if (send_ret == 0) {
			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		err = errno;
		if (err != EAGAIN)
			pr_err("sendto(): " PRERF, PREAR(err));

		return -err;
	}

	return send_ret;
}


static int emergency_wait_for_tun_fd_be_writable(struct epl_thread *thread,
						 int tun_fd)
{
	int ret;
	const int timeout = 30000;
	struct srv_udp_state *state = thread->state;

	pr_emerg("[thread=%hu] write(tun_fd=%d) got EAGAIN", thread->idx,
		 tun_fd);

	state->in_emergency = true;
	if (state->stop)
		goto give_up;

	pr_emerg("[thread=%hu] Sleeping on poll(), waiting for tun_fd be "
		 "writable...", thread->idx);

	ret = wait_for_fd_be_writable(tun_fd, timeout);
	if (ret == 0)
		return ret;

	state->stop = true;
	pr_err("wait_for_fd_be_writable(): " PRERF, PREAR(-ret));

give_up:
	pr_emerg("Giving up...");
	return -ENETDOWN;
}


static int emergency_wait_for_udp_fd_be_writable(struct epl_thread *thread)
{
	int ret;
	const int timeout = 30000;
	int udp_fd = thread->state->udp_fd;
	struct srv_udp_state *state = thread->state;

	pr_emerg("[thread=%hu] sendto(udp_fd=%d) got EAGAIN", thread->idx,
		 udp_fd);

	state->in_emergency = true;
	if (state->stop)
		goto give_up;

	pr_emerg("[thread=%hu] Sleeping on poll(), waiting for udp_fd be "
		 "writable...", thread->idx);

	ret = wait_for_fd_be_writable(udp_fd, timeout);
	if (ret == 0)
		return ret;

	state->stop = true;
	pr_err("wait_for_fd_be_writable(): " PRERF, PREAR(-ret));

give_up:
	pr_emerg("Giving up...");
	return -ENETDOWN;
}


static ssize_t send_to_client(struct epl_thread *thread,
			      struct udp_sess *sess, const void *buf,
			      size_t pkt_len)
{
	ssize_t send_ret;
	struct sockaddr *dst_addr = (struct sockaddr *)&sess->addr;

send_again:
	send_ret = _send_to_client(thread->state, buf, pkt_len, dst_addr);
	if (unlikely(send_ret < 0)) {

		if (send_ret == -EAGAIN) {
			int ret = emergency_wait_for_udp_fd_be_writable(thread);
			if (ret == 0)
				goto send_again;

			return ret;
		}

		pr_err("[thread=%hu] send_to_client() " PRWIU " " PRERF,
		       thread->idx, W_IU(sess), PREAR((int)send_ret));
		return send_ret;
	}

	thread->state->in_emergency = false;
	pr_debug("[thread=%hu] sendto(udp_fd=%d) %zd bytes to " PRWIU,
		 thread->idx, thread->state->udp_fd, send_ret, W_IU(sess));

	return send_ret;
}


static int close_udp_session(struct epl_thread *thread, struct udp_sess *sess)
{
	size_t send_len;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	prl_notice(2, "Closing connection from " PRWIU "...", W_IU(sess));

	if (sess->ipv4_iff != 0)
		del_ipv4_route_map(thread->state->ipv4_map, sess->ipv4_iff);

	send_len = srv_pprep(srv_pkt, TSRV_PKT_CLOSE, 0, 0);
	send_to_client(thread, sess, srv_pkt, send_len);
	return delete_udp_session(thread->state, sess);
}


static ssize_t _do_recv_from(int udp_fd, char *buf, size_t recv_size,
			     struct sockaddr *src_addr, socklen_t *saddr_len)
{
	int ret;
	ssize_t recv_ret;

	if (unlikely(recv_size == 0))
		return 0;

	recv_ret = recvfrom(udp_fd, buf, recv_size, 0, src_addr, saddr_len);
	if (unlikely(recv_ret < 0)) {

		if (recv_ret == 0) {
			pr_err("UDP socket has been disconnected!");
			return -ENETDOWN;
		}

		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_err("recvfrom(udp_fd) (fd=%d): " PRERF, udp_fd, PREAR(ret));
		return (ssize_t)-ret;
	}

	return recv_ret;
}


static ssize_t do_recv_from(struct epl_thread *thread,
			    int udp_fd, struct sockaddr_in *saddr,
			    socklen_t *saddr_len)
{
	ssize_t recv_ret;
	char *buf = thread->pkt->__raw;
	struct sockaddr *src_addr = (struct sockaddr *)saddr;
	const size_t recv_size = sizeof(thread->pkt->cli.__raw);

	recv_ret = _do_recv_from(udp_fd, buf, recv_size, src_addr, saddr_len);
	if (unlikely(recv_ret < 0))
		return recv_ret;

	thread->pkt->len = (size_t)recv_ret;
	pr_debug("[thread=%hu] recvfrom(udp_fd=%d) %zd bytes", thread->idx,
		 udp_fd, recv_ret);

	return recv_ret;
}


static int send_handshake(struct epl_thread *thread, struct udp_sess *sess)
{
	size_t send_len;
	ssize_t send_ret;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	send_len = srv_pprep_handshake(srv_pkt);
	send_ret = send_to_client(thread, sess, srv_pkt, send_len);
	if (unlikely(send_ret < 0))
		return (int)send_ret;

	return 0;
}


static int send_handshake_reject(struct epl_thread *thread,
				 struct udp_sess *sess, uint8_t reason,
				 const char *msg)
{
	size_t send_len;
	ssize_t send_ret;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	send_len = srv_pprep_handshake_reject(srv_pkt, reason, msg);
	send_ret = send_to_client(thread, sess, srv_pkt, send_len);
	if (unlikely(send_ret < 0))
		return (int)send_ret;

	return 0;
}


static int handle_client_handshake(struct epl_thread *thread,
				   struct udp_sess *sess)
{
	int ret;
	char rej_msg[512];
	uint8_t rej_reason = 0;
	size_t len = thread->pkt->len;
	struct cli_pkt *cli_pkt = &thread->pkt->cli;
	struct pkt_handshake *hand = &cli_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;
	const size_t expected_len = sizeof(*hand);

	if (len < (PKT_MIN_LEN + expected_len)) {
		snprintf(rej_msg, sizeof(rej_msg),
			 "Invalid handshake packet length from " PRWIU
			 " (expected at least %zu bytes; actual = %zu bytes)",
			 W_IU(sess), (PKT_MIN_LEN + expected_len), len);

		ret = -EBADMSG;
		rej_reason = TSRV_HREJECT_INVALID;
		goto reject;
	}

	cli_pkt->len = ntohs(cli_pkt->len);
	if (((size_t)cli_pkt->len) != expected_len) {
		snprintf(rej_msg, sizeof(rej_msg),
			 "Invalid handshake packet length from " PRWIU
			 " (expected = %zu; actual: cli_pkt->len = %hu)",
			 W_IU(sess), expected_len, cli_pkt->len);

		ret = -EBADMSG;
		rej_reason = TSRV_HREJECT_INVALID;
		goto reject;
	}

	if (cli_pkt->type != TCLI_PKT_HANDSHAKE) {
		snprintf(rej_msg, sizeof(rej_msg),
			 "Invalid first packet type from " PRWIU
			 " (expected = TCLI_PKT_HANDSHAKE (%u); actual = %hhu)",
			 W_IU(sess), TCLI_PKT_HANDSHAKE, cli_pkt->type);

		ret = -EBADMSG;
		rej_reason = TSRV_HREJECT_INVALID;
		goto reject;
	}

	/* For printing safety! */
	cur->extra[sizeof(cur->extra) - 1] = '\0';
	prl_notice(2, "New connection from " PRWIU
		   " (client version: TeaVPN2-%hhu.%hhu.%hhu%s)",
		   W_IU(sess),
		   cur->ver,
		   cur->patch_lvl,
		   cur->sub_lvl,
		   cur->extra);

	if ((cur->ver != VERSION) || (cur->patch_lvl != PATCHLEVEL) ||
	    (cur->sub_lvl != SUBLEVEL)) {
		ret = -EBADMSG;
		rej_reason = TSRV_HREJECT_VERSION_NOT_SUPPORTED;
		prl_notice(2, "Dropping connection from " PRWIU
			   " (version not supported)...", W_IU(sess));
		goto reject;
	}


	/*
	 * Good handshake packet, send back.
	 */
	return send_handshake(thread, sess);

reject:
	prl_notice(2, "%s", rej_msg);
	send_handshake_reject(thread, sess, rej_reason, rej_msg);
	return ret;
}


static int _handle_new_client(struct epl_thread *thread, struct udp_sess *sess)
{
	int ret = 0;

	ret = handle_client_handshake(thread, sess);
	if (ret) {
		/*
		 * Handshake failed, drop the client session!
		 */
		close_udp_session(thread, sess);

		/*
		 * If the handle_client_handshake() returns -EBADMSG,
		 * this means the client has sent bad handshake packet.
		 * It's not our fault, so return 0 as we are still fine.
		 */
		ret = (ret == -EBADMSG) ? 0 : ret;
	}

	return ret;
}


static inline bool skip_session_creation(struct epl_thread *thread)
{
	struct cli_pkt *cli_pkt = &thread->pkt->cli;
	uint8_t type = cli_pkt->type;
	return (
		type == TCLI_PKT_TUN_DATA	||
		type == TCLI_PKT_REQSYNC	||
		type == TCLI_PKT_SYNC		||
		type == TCLI_PKT_CLOSE
	);
}


static int handle_new_client(struct epl_thread *thread, uint32_t addr,
			     uint16_t port, struct sockaddr_in *saddr)
{
	int ret;
	struct udp_sess *sess;

	if (skip_session_creation(thread))
		return 0;

	sess = create_udp_sess(thread->state, addr, port);
	if (unlikely(!sess)) {
		ret = errno;
		return (ret == EAGAIN) ? 0 : -ret;
	}
	sess->addr = *saddr;

#ifndef NDEBUG
	/*
	 * After calling create_udp_sess(), we must have it
	 * on the map. If we don't have, then it's a bug!
	 */
	BUG_ON(lookup_udp_sess(thread->state, addr, port) != sess);
#endif
	return _handle_new_client(thread, sess);
}


static int handle_clpkt_auth(struct epl_thread *thread, struct udp_sess *sess)
{
	int ret = 0;
	size_t send_len;
	ssize_t send_ret;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;
	struct cli_pkt *cli_pkt = &thread->pkt->cli;
	struct pkt_auth_res *auth_res = &srv_pkt->auth_res;
	struct pkt_auth auth = cli_pkt->auth;

	if (sess->is_authenticated) {
		/*
		 * If the client has already been authenticated,
		 * this will be a no-op.
		 */
		return 0;
	}

	/* Ensure we have NUL terminated credentials. */
	auth.username[sizeof(auth.username) - 1] = '\0';
	auth.password[sizeof(auth.password) - 1] = '\0';

	prl_notice(2, "Got auth packet from (user: %s) " PRWIU, auth.username,
		   W_IU(sess));

	if (!teavpn2_auth(auth.username, auth.password, &auth_res->iff))
		goto reject;

	/*
	 * Auth ok!
	 */
	send_len = srv_pprep(srv_pkt, TSRV_PKT_AUTH_OK, sizeof(*auth_res), 0);
	send_ret = send_to_client(thread, sess, srv_pkt, send_len);
	if (unlikely(send_ret < 0)) {
		ret = (int)send_ret;
		close_udp_session(thread, sess);
		goto out;
	}

	sess->ipv4_iff = ntohl(inet_addr(auth_res->iff.ipv4));
	add_ipv4_route_map(thread->state->ipv4_map, sess->ipv4_iff, sess->idx);

	sess->is_authenticated = true;
	strncpy2(sess->username, auth.username, sizeof(sess->username));
	goto out;


reject:
	/* 
	 * Auth fails!
	 */
	send_len = srv_pprep(srv_pkt, TSRV_PKT_AUTH_REJECT, 0, 0);
	send_ret = send_to_client(thread, sess, srv_pkt, send_len);
	if (unlikely(send_ret < 0))
		ret = (int)send_ret;

	prl_notice(2, "Authentication failed for username \"%s\" " PRWIU,
		   auth.username, W_IU(sess));
	close_udp_session(thread, sess);


out:
	memset(auth.password, 0, sizeof(auth.password));
	__asm__ volatile("":"+m"(auth.password)::"memory");
	return ret;
}


static ssize_t _handle_clpkt_tun_data(struct epl_thread *thread, int tun_fd)
{
	uint16_t data_len;
	ssize_t write_ret;

	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	data_len = ntohs(srv_pkt->len);
	if (unlikely(data_len == 0))
		return 0;

	write_ret = write(tun_fd, srv_pkt->__raw, (size_t)data_len);
	if (unlikely(write_ret <= 0)) {
		int err;

		if (write_ret == 0) {
			pr_err("write() to TUN fd returned zero");
			return -ENETDOWN;
		}

		err = errno;
		if (err != EAGAIN)
			pr_err("write(): " PRERF, PREAR(err));

		return (ssize_t)-err;
	}
	return write_ret;
}


static int handle_clpkt_tun_data(struct epl_thread *thread,
				 struct udp_sess *sess)
{	
	ssize_t write_ret;
	int tun_fd = thread->state->tun_fds[0];

write_again:
	write_ret = _handle_clpkt_tun_data(thread, tun_fd);
	if (unlikely(write_ret < 0)) {

		if (write_ret == -EAGAIN) {
			int ret = emergency_wait_for_tun_fd_be_writable(thread,
									tun_fd);
			if (ret == 0)
				goto write_again;

			return ret;
		}

		pr_err("[thread=%hu] write(tun_fd=%d) data from " PRWIU " "
		       PRERF, thread->idx, tun_fd, W_IU(sess),
		       PREAR((int)write_ret));

		return (int)write_ret;
	}

	pr_debug("[thread=%hu] write(tun_fd=%d) %zd bytes", thread->idx,
		 tun_fd, write_ret);

	return 0;
}


/*
 * Handle request sync from client.
 * If the client requests a sync, we (the server) send a sync packet.
 */
static int handle_clpkt_reqsync(struct epl_thread *thread, struct udp_sess *sess)
{
	int ret = 0;
	size_t send_len;
	ssize_t send_ret;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	send_len = srv_pprep_sync(srv_pkt);
	send_ret = send_to_client(thread, sess, srv_pkt, send_len);
	if (unlikely(send_ret < 0))
		ret = (int)send_ret;

	return ret;
}


static int __handle_event_from_udp(struct epl_thread *thread,
				   struct udp_sess *sess)
{
	int ret = 0;
	struct cli_pkt *cli_pkt = &thread->pkt->cli;

	switch (cli_pkt->type) {
	case TCLI_PKT_HANDSHAKE:
		return 0;
	case TCLI_PKT_AUTH:
		return handle_clpkt_auth(thread, sess);
	case TCLI_PKT_TUN_DATA:
		return handle_clpkt_tun_data(thread, sess);
	case TCLI_PKT_REQSYNC:
		ret = handle_clpkt_reqsync(thread, sess);
		fallthrough;
	case TCLI_PKT_SYNC:
		udp_sess_update_last_act(sess);
		return ret;
	case TCLI_PKT_CLOSE:
		close_udp_session(thread, sess);
		return 0;
	default:
		/* Bad packet! */
		return -EBADMSG;
	}
}


static int _handle_event_from_udp(struct epl_thread *thread,
				  struct sockaddr_in *saddr)
{
	int ret;
	uint32_t addr;
	uint16_t port;
	struct udp_sess *sess;

	port = ntohs(saddr->sin_port);
	addr = ntohl(saddr->sin_addr.s_addr);
	sess = lookup_udp_sess(thread->state, addr, port);
	if (unlikely(!sess)) {
		/*
		 * It's a new client because we don't find it on
		 * the session map.
		 */
		return handle_new_client(thread, addr, port, saddr);
	}

	ret = __handle_event_from_udp(thread, sess);
	if (unlikely(ret < 0)) {
		if (ret == -EBADMSG) {
			close_udp_session(thread, sess);
			return 0;
		}
		return ret;
	}

	if ((++sess->loop_c % 32) == 0) {
		size_t send_len;
		struct srv_pkt *srv_pkt = &thread->pkt->srv;

		udp_sess_update_last_act(sess);
		send_len = srv_pprep_sync(srv_pkt);
		send_to_client(thread, sess, srv_pkt, send_len);
		pr_debug("Syncing with " PRWIU, W_IU(sess));
	}

	return ret;
}


static int handle_event_from_udp(struct epl_thread *thread, int udp_fd)
{
	ssize_t recv_ret;
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);

	recv_ret = do_recv_from(thread, udp_fd, &saddr, &saddr_len);
	if (unlikely(recv_ret <= 0))
		return (int)recv_ret;

	return _handle_event_from_udp(thread, &saddr);
}


/*
 * return -ENOENT if cannot find the destination.
 * return 0 if it finds the destination.
 * return -errno if it errors.
 */
static int route_ipv4_packet(struct epl_thread *thread, __be32 dst_addr,
			     struct udp_sess *sess_arr, size_t send_len)
{
	uint16_t idx;
	int32_t find;
	ssize_t send_ret;
	struct udp_sess *dst_sess;

	find = get_ipv4_route_map(thread->state->ipv4_map, dst_addr);
	if (unlikely(find < 0))
		return (int)find;

	idx      = (uint16_t)find;
	dst_sess = &sess_arr[idx];
	send_ret = send_to_client(thread, dst_sess, &thread->pkt->srv, send_len);
	if (send_ret < 0)
		return (int)send_ret;

	return 0;
}


static int broadcast_packet(struct epl_thread *thread, size_t send_len)
{
	struct srv_pkt *srv_pkt = &thread->pkt->srv;
	struct srv_udp_state *state = thread->state;
	struct udp_sess	*sess_arr = state->sess_arr;
	uint16_t i, max_conn = state->cfg->sock.max_conn;

	/*
	 * Broadcast this to all authenticated clients.
	 */
	for (i = 0; i < max_conn; i++) {
		ssize_t send_ret;
		struct udp_sess	*sess = &sess_arr[i];

		if (!sess->is_authenticated)
			continue;

		send_ret = send_to_client(thread, sess, srv_pkt, send_len);
		if (unlikely(send_ret < 0))
			return (int)send_ret;
	}

	return 0;
}


static int _route_packet(struct epl_thread *thread, size_t send_len)
{
	struct srv_pkt *srv_pkt = &thread->pkt->srv;
	struct iphdr *iphdr = &srv_pkt->tun_data.iphdr;

	if (likely(iphdr->version == 4)) {
		int ret;
		uint32_t dst_addr = ntohl(iphdr->daddr);
		struct udp_sess	*sess_arr = thread->state->sess_arr;

		ret = route_ipv4_packet(thread, dst_addr, sess_arr, send_len);
		if (likely(ret != -ENOENT))
			return ret;
	}

	return broadcast_packet(thread, send_len);
}


static int route_packet(struct epl_thread *thread, ssize_t len)
{
	size_t send_len;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	send_len = srv_pprep(srv_pkt, TSRV_PKT_TUN_DATA, (uint16_t)len, 0);
	return _route_packet(thread, send_len);
}


static int handle_event_from_tun(struct epl_thread *thread, int tun_fd)
{
	int ret;
	ssize_t read_ret;
	char *buf = thread->pkt->srv.__raw;
	const size_t read_size = sizeof(thread->pkt->srv.__raw);

	read_ret = read(tun_fd, buf, read_size);
	if (unlikely(read_ret < 0)) {
		ret = errno;
		if (likely(ret == EAGAIN))
			return 0;

		pr_err("read(tun_fd) (fd=%d): " PRERF, tun_fd, PREAR(ret));
		return -ret;
	}

	thread->pkt->len = (size_t)read_ret;
	pr_debug("[thread=%hu] read(tun_fd=%d) = %zd bytes", thread->idx,
		 tun_fd, read_ret);

	return route_packet(thread, read_ret);
}


static int handle_event(struct epl_thread *thread, struct epoll_event *event)
{
	int ret = 0;
	int fd = event->data.fd;

	if (fd == thread->state->udp_fd)
		ret = handle_event_from_udp(thread, fd);
	else
		ret = handle_event_from_tun(thread, fd);

	return ret;
}


static int do_epoll_wait(struct epl_thread *thread)
{
	int ret;
	int epoll_fd = thread->epoll_fd;
	int timeout = thread->epoll_timeout;
	struct epoll_event *events = thread->events;

	ret = epoll_wait(epoll_fd, events, EPOLL_EVT_ARR_NUM, timeout);
	if (unlikely(ret < 0)) {
		ret = errno;

		if (likely(ret == EINTR)) {
			prl_notice(2, "[thread=%hu] Interrupted!", thread->idx);
			return 0;
		}

		pr_err("[thread=%u] epoll_wait(): " PRERF, thread->idx,
		       PREAR(ret));
		return -ret;
	}
	return ret;
}


static int __run_event_loop(struct epl_thread *thread)
{
	int i, ret, tmp;
	struct epoll_event *events;

	ret = do_epoll_wait(thread);
	if (unlikely(ret < 0))
		return ret;

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = handle_event(thread, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}


static noinline void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread;
	struct srv_udp_state *state;

	thread = (struct epl_thread *)thread_p;
	state  = thread->state;

	atomic_store(&thread->is_online, true);
	atomic_fetch_add(&state->n_on_threads, 1);

	while (likely(!state->stop)) {
		ret = __run_event_loop(thread);
		if (unlikely(ret))
			break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->n_on_threads, 1);
	return (void *)((intptr_t)ret);
}


static void zr_send_reqsync(struct srv_udp_state *state, struct udp_sess *sess)
{
	size_t send_len;
	struct srv_pkt *srv_pkt = &state->zr.pkt->srv;

	prl_notice(5, "[zombie reaper] Sending req sync to " PRWIU "...",
		   W_IU(sess));

	send_len = srv_pprep(srv_pkt, TSRV_PKT_REQSYNC, 0, 0);
	send_to_client(&state->epl_threads[0], sess, srv_pkt, send_len);
}


static int zr_close_sess(struct srv_udp_state *state, struct udp_sess *sess)
{
	size_t send_len;
	struct srv_pkt *srv_pkt = &state->zr.pkt->srv;

	prl_notice(2, "[zombie reaper] Closing session " PRWIU " (no activity)...",
		   W_IU(sess));

	if (sess->ipv4_iff != 0)
		del_ipv4_route_map(state->ipv4_map, sess->ipv4_iff);

	send_len = srv_pprep(srv_pkt, TSRV_PKT_CLOSE, 0, 0);
	send_to_client(&state->epl_threads[0], sess, srv_pkt, send_len);
	return delete_udp_session(state, sess);
}


static void zr_chk_auth(struct srv_udp_state *state, struct udp_sess *sess,
			time_t time_diff)
{
	const time_t max_diff = UDP_SESS_TIMEOUT_AUTH;

	if (time_diff > max_diff) {
		zr_close_sess(state, sess);
		return;
	}

	if (time_diff > ((max_diff * 3) / 4))
		zr_send_reqsync(state, sess);
}


static void zr_chk_no_auth(struct srv_udp_state *state, struct udp_sess *sess,
			   time_t time_diff)
{
	const time_t max_diff = UDP_SESS_TIMEOUT_NO_AUTH;

	if (time_diff > max_diff)
		zr_close_sess(state, sess);
}


static void zombie_reaper_do_scan(struct srv_udp_state *state)
{
	uint16_t i, j, max_conn = state->cfg->sock.max_conn;
	struct udp_sess *sess, *sess_arr = state->sess_arr;

	for (i = j = 0; i < max_conn; i++) {
		time_t time_diff = 0;

		sess = &sess_arr[i];
		if (!atomic_load(&sess->is_connected))
			continue;

		get_unix_time(&time_diff);
		time_diff -= sess->last_act;

		if (sess->is_authenticated)
			zr_chk_auth(state, sess, time_diff);
		else
			zr_chk_no_auth(state, sess, time_diff);
	}
}


static void *run_zombie_reaper_thread(void *arg)
{
	struct srv_udp_state *state = (struct srv_udp_state *)arg;

	if (nice(40) < 0) {
		int err = errno;
		pr_warn("nice(40) = " PRERF, PREAR(err));
	}

	atomic_store(&state->zr.is_online, true);

	state->zr.pkt = calloc_wrp(1ul, sizeof(*state->zr.pkt));
	if (unlikely(!state->zr.pkt))
		state->stop = true;

	while (likely(!state->stop)) {
		sleep(5);
		if (!state->in_emergency) {
			pr_debug("[zombie reaper] Scanning...");
			zombie_reaper_do_scan(state);
		}
	}

	al64_free(state->zr.pkt);
	atomic_store(&state->zr.is_online, false);
	return NULL;
}


static int spawn_zombie_reaper_thread(struct srv_udp_state *state)
{
	int ret;
	pthread_t *tr = &state->zr.thread;

	prl_notice(2, "Spawning zombie reaper thread...");
	ret = pthread_create(tr, NULL, run_zombie_reaper_thread, state);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(*tr);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	pthread_setname_np(*tr, "zombie-reaper");
	return ret;
}


static int spawn_tun_worker_thread(struct epl_thread *thread)
{
	int ret;
	char buf[sizeof("tun-worker-xxxx")];
	pthread_t *tr = &thread->thread;

	prl_notice(2, "Spawning thread %u...", thread->idx);
	ret = pthread_create(tr, NULL, _run_event_loop, thread);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(*tr);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	snprintf(buf, sizeof(buf), "tun-worker-%hu", thread->idx);
	pthread_setname_np(*tr, buf);
	return ret;
}


static int run_event_loop(struct srv_udp_state *state)
{
	int ret;
	void *ret_p;
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	ret = spawn_zombie_reaper_thread(state);
	if (unlikely(ret))
		goto out;

	atomic_store(&state->n_on_threads, 0);
	for (i = 1; i < nn; i++) {
		/*
		 * Spawn the subthreads.
		 * 
		 * For @i == 0, it is the main thread,
		 * don't spawn pthread for it.
		 */
		ret = spawn_tun_worker_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
out:
	return ret;
}


static bool wait_for_zombie_reaper_thread_to_exit(struct srv_udp_state *state)
{
	int ret;
	unsigned wait_c = 0;

	if (atomic_load(&state->zr.is_online)) {
		ret = pthread_kill(state->zr.thread, SIGTERM);
		if (unlikely(ret)) {
			pr_err("pthread_kill(state->zr.thread, SIGTERM): "
			       PRERF, PREAR(ret));
		}

		prl_notice(2, "Waiting for zombie reaper thread to exit...");

		while (atomic_load(&state->zr.is_online)) {
			usleep(100000);
			if (wait_c++ > 1000)
				return false;
		}
	}

	return true;
}


static bool wait_for_tun_worker_threads_to_exit(struct srv_udp_state *state)
{
	int ret;
	uint8_t nn, i;
	unsigned wait_c = 0;
	uint16_t thread_on = 0, cc;
	struct epl_thread *threads;

	thread_on = atomic_load(&state->n_on_threads);
	if (thread_on == 0)
		/*
		 * All threads have exited, it's good.
		 */
		return true;

	threads = state->epl_threads;
	nn = state->cfg->sys.thread_num;
	for (i = 0; i < nn; i++) {

		if (!atomic_load(&threads[i].is_online))
			continue;

		ret = pthread_kill(threads[i].thread, SIGTERM);
		if (unlikely(ret)) {
			pr_err("pthread_kill(threads[%hhu].thread, SIGTERM): "
			       PRERF, i, PREAR(ret));
		}
	}


	prl_notice(2, "Waiting for %hu thread(s) to exit...", thread_on);
	while ((cc = atomic_load(&state->n_on_threads)) > 0) {

		if (cc != thread_on) {
			thread_on = cc;
			prl_notice(2, "Waiting for %hu thread(s) to exit...",
				   cc);
		}

		usleep(100000);
		if (wait_c++ > 1000)
			return false;
	}
	return true;
}


static bool wait_for_threads_to_exit(struct srv_udp_state *state)
{

	if (!wait_for_zombie_reaper_thread_to_exit(state))
		return false;

	if (!wait_for_tun_worker_threads_to_exit(state))
		return false;

	return true;
}


static void close_epoll_fds(struct srv_udp_state *state)
{
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	if (unlikely(!threads))
		return;

	for (i = 0; i < nn; i++) {
		int epoll_fd = threads[i].epoll_fd;

		if (epoll_fd == -1)
			continue;

		prl_notice(2, "Closing epoll_fd (fd=%d)...", epoll_fd);
		close(epoll_fd);
	}
}


static void close_client_sess(struct srv_udp_state *state)
{
	struct udp_sess *sess_arr = state->sess_arr;
	uint16_t i, max_conn = state->cfg->sock.max_conn;

	if (unlikely(!sess_arr))
		return;

	for (i = 0; i < max_conn; i++) {

		if (!atomic_load(&sess_arr[i].is_connected))
			continue;

		close_udp_session(&state->epl_threads[0], &sess_arr[i]);
	}
}


static void free_pkt_buffer(struct srv_udp_state *state)
{
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	if (unlikely(!threads))
		return;

	for (i = 0; i < nn; i++)
		al4096_free_munmap(threads[i].pkt, sizeof(*threads[i].pkt));
}


static void destroy_epoll(struct srv_udp_state *state)
{
	if (!wait_for_threads_to_exit(state)) {
		/*
		 * Thread(s) won't exit, don't free the heap!
		 */
		pr_emerg("Thread(s) won't exit!");
		state->threads_wont_exit = true;
		return;
	}

	close_epoll_fds(state);
	close_client_sess(state);
	free_pkt_buffer(state);
	al64_free(state->epl_threads);
}


int teavpn2_udp_server_epoll(struct srv_udp_state *state)
{
	int ret;

	ret = init_epoll_thread_array(state);
	if (unlikely(ret))
		goto out;

	state->stop = false;
	ret = run_event_loop(state);
out:
	destroy_epoll(state);
	return ret;
}

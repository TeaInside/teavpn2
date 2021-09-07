// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
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


static int do_epoll_fd_registration(struct srv_udp_state *state,
				    struct epl_thread *thread)
{
	int ret;
	epoll_data_t data;
	int *tun_fds = state->tun_fds;
	const uint32_t events = EPOLLIN | EPOLLPRI;

	memset(&data, 0, sizeof(data));

	if (unlikely(state->cfg->sys.thread_num < 1)) {
		panic("Invalid thread num (%hhu)", state->cfg->sys.thread_num);
		__builtin_unreachable();
	}

	if (thread->idx == 0) {

		/*
		 * Main thread is responsible to handle data
		 * from UDP socket.
		 */
		data.fd = state->udp_fd;
		ret = epoll_add(thread, data.fd, events, data);
		if (unlikely(ret))
			return ret;

		if (state->cfg->sys.thread_num == 1) {
			/*
			 * If we are singlethreaded, the main thread
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


static int init_epoll_thread(struct srv_udp_state *state,
			     struct epl_thread *thread)
{
	int ret;

	ret = create_epoll_fd();
	if (unlikely(ret < 0))
		return ret;

	thread->epoll_fd = ret;
	thread->epoll_timeout = 10000;

	ret = do_epoll_fd_registration(state, thread);
	if (unlikely(ret))
		return ret;

	return 0;
}


static int init_epoll_thread_array(struct srv_udp_state *state)
{
	int ret = 0;
	struct epl_thread *threads;
	uint8_t i, nn = state->cfg->sys.thread_num;

	state->epl_threads = NULL;
	threads = calloc_wrp((size_t)nn, sizeof(*threads));
	if (unlikely(!threads))
		return -errno;


	state->epl_threads = threads;

	/*
	 * Initialize all epoll_fd to -1 for graceful clean up in
	 * case we fail to create the epoll instance.
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

		pkt = calloc_wrp(1ul, sizeof(*pkt));
		if (unlikely(!pkt))
			return -errno;

		threads[i].pkt = pkt;
	}

	return ret;
}


static int _do_epoll_wait(struct epl_thread *thread)
{
	int ret;
	int epoll_fd = thread->epoll_fd;
	int timeout = thread->epoll_timeout;
	struct epoll_event *events = thread->events;

	ret = epoll_wait(epoll_fd, events, EPOLL_EVT_ARR_NUM, timeout);
	if (unlikely(ret < 0)) {
		ret = errno;

		if (likely(ret == EINTR)) {
			prl_notice(2, "[thread=%u] Interrupted!", thread->idx);
			return 0;
		}

		pr_err("[thread=%u] epoll_wait(): " PRERF, thread->idx,
		       PREAR(ret));
		return -ret;
	}

	return ret;
}


static ssize_t send_to_client(struct epl_thread *thread,
			      struct udp_sess *sess, const void *buf,
			      size_t pkt_len)
{
	int err;
	ssize_t send_ret;
	uint32_t emergency_count = 0;
	socklen_t len = sizeof(sess->addr);
	struct sockaddr *dst_addr = (struct sockaddr *)&sess->addr;

send_again:
	send_ret = sendto(thread->state->udp_fd, buf, pkt_len, 0, dst_addr, len);
	if (unlikely(send_ret <= 0)) {

		if (send_ret == 0) {
			if (pkt_len == 0)
				return 0;

			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		err = errno;
		if (err == EAGAIN) {
			thread->state->in_emergency = true;

			if (emergency_count++ == 0) {
				pr_emerg("UDP buffer is full, cannot send!");
				pr_emerg("Initiate soft loop on sys_sendto...");
			}

			if (emergency_count > 5000) {
				pr_emerg("Giving up, cannot write to UDP fd...");
				return -ENETDOWN;
			}

			/* Calm down a bit... */
			usleep(100000);
			goto send_again;
		}

		pr_err("sendto(): " PRERF, PREAR(err));
		return (ssize_t)-err;
	}

	pr_debug("[thread=%hu] sendto() %zd bytes to " PRWIU, thread->idx,
		 send_ret, W_IU(sess));

	if (unlikely(emergency_count > 0)) {
		thread->state->in_emergency = false;
		pr_emerg("Recovered from EAGAIN!");
	}

	return send_ret;
}


static int close_udp_session(struct epl_thread *thread, struct udp_sess *sess)
{
	size_t send_len;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	if (sess->ipv4_iff != 0)
		del_ipv4_route_map(thread->state->ipv4_map, sess->ipv4_iff);

	send_len = srv_pprep(srv_pkt, TSRV_PKT_CLOSE, 0, 0);
	send_to_client(thread, sess, srv_pkt, send_len);
	return put_udp_session(thread->state, sess);
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


static int handle_new_client(struct epl_thread *thread,
			     struct srv_udp_state *state, uint32_t addr,
			     uint16_t port, struct sockaddr_in *saddr)
{
	int ret;
	struct udp_sess *sess;

	sess = get_udp_sess(thread->state, addr, port);
	if (unlikely(!sess))
		return -errno;

	sess->addr = *saddr;

#ifndef NDEBUG
	/*
	 * After calling get_udp_sess(), we must have it
	 * on the map. If we don't, then it's a bug!
	 */
	BUG_ON(map_find_udp_sess(state, addr, port) != sess);
#endif

	ret = handle_client_handshake(thread, sess);
	if (ret) {
		/*
		 * Handshake failed, drop the client session!
		 */
		close_udp_session(thread, sess);
		ret = (ret == -EBADMSG) ? 0 : ret;
	}

	return ret;
}


static int handle_tun_data(struct epl_thread *thread, struct udp_sess *sess)
{
	uint16_t data_len;
	ssize_t write_ret;
	uint32_t emergency_count = 0;
	int tun_fd = thread->state->tun_fds[0];
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	data_len  = ntohs(srv_pkt->len);

write_again:
	write_ret = write(tun_fd, srv_pkt->__raw, data_len);
	if (unlikely(write_ret <= 0)) {
		int err = errno;

		if (write_ret == 0) {
			if (data_len == 0)
				return 0;

			pr_err("write() to TUN fd returned zero");
			return -ENETDOWN;
		}

		if (err == EAGAIN) {
			thread->state->in_emergency = true;

			if (emergency_count++ == 0) {
				pr_emerg("TUN buffer is full, cannot write!");
				pr_emerg("Initiate soft loop on sys_write...");
			}

			if (emergency_count > 5000) {
				pr_emerg("Giving up, cannot write to TUN fd...");
				return -ENETDOWN;
			}

			/* Calm down a bit... */
			usleep(100000);
			goto write_again;
		}

		prl_notice(4, "Bad packet from " PRWIU ", write(): " PRERF,
			   W_IU(sess), PREAR(err));

		if (++sess->err_c > UDP_SESS_MAX_ERR)
			close_udp_session(thread, sess);

		return 0;
	}

	pr_debug("[thread=%u] TUN write(%d, buf, %hu) = %zd bytes", thread->idx,
		 tun_fd, data_len, write_ret);

	if (unlikely(emergency_count > 0)) {
		thread->state->in_emergency = false;
		pr_emerg("Recovered from EAGAIN!");
	}

	return 0;
}


static int __handle_event_udp(struct epl_thread *thread,
			      struct srv_udp_state *state,
			      struct udp_sess *sess)
{
	struct cli_pkt *cli_pkt = &thread->pkt->cli;
	(void)state;

	switch (cli_pkt->type) {
	case TCLI_PKT_HANDSHAKE:
		/*
		 * We have done the protocol handshake, this is a no-op.
		 */
		return 0;
	case TCLI_PKT_AUTH:
		return handle_clpkt_auth(thread, sess);
	case TCLI_PKT_TUN_DATA:
		return handle_tun_data(thread, sess);
	case TCLI_PKT_REQSYNC:
		return 0;
	case TCLI_PKT_SYNC:
		return 0;
	case TCLI_PKT_PING:
		return sess->is_authenticated ? 0 : -EBADRQC;
	case TCLI_PKT_CLOSE:
		close_udp_session(thread, sess);
		return 0;
	default:

		if (sess->is_authenticated) {
			/*
			 * If an authenticated client sends an invalid packet,
			 * give it a chance to sync. It could be a bit network
			 * problem.
			 */
			// return request_sync(thread, sess);
			return 0;
		}

		/* Bad packet! */
		return -EBADRQC;
	}
}


static int _handle_event_udp(struct epl_thread *thread,
			     struct srv_udp_state *state,
			     struct sockaddr_in *saddr)
{
	int ret;
	uint16_t port;
	uint32_t addr;
	struct udp_sess *sess;

	port = ntohs(saddr->sin_port);
	addr = ntohl(saddr->sin_addr.s_addr);
	sess = map_find_udp_sess(state, addr, port);
	if (unlikely(!sess)) {
		/*
		 * It's a new client since we don't find it in
		 * the session map.
		 */
		ret = handle_new_client(thread, state, addr, port, saddr);
		return (ret == -EAGAIN) ? 0 : ret;
	}

	ret = __handle_event_udp(thread, state, sess);
	if (unlikely(ret)) {
		if (ret == -EBADRQC) {
			close_udp_session(thread, sess);
			return 0;
		}
		return ret;
	}

	return 0;
}


static ssize_t do_recvfrom(struct epl_thread *thread,
			   int udp_fd, struct sockaddr_in *saddr,
			   socklen_t *saddr_len)
{
	int ret;
	ssize_t recv_ret;
	char *buf = thread->pkt->__raw;
	struct sockaddr *src_addr = (struct sockaddr *)saddr;
	const size_t recv_size = sizeof(thread->pkt->cli.__raw);

	recv_ret = recvfrom(udp_fd, buf, recv_size, 0, src_addr, saddr_len);
	if (unlikely(recv_ret <= 0)) {

		if (recv_ret == 0) {
			if (recv_size == 0)
				return 0;

			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_err("recvfrom(udp_fd) (fd=%d): " PRERF, udp_fd, PREAR(ret));
		return -ret;
	}

	thread->pkt->len = (size_t)recv_ret;
	pr_debug("[thread=%hu] recvfrom() %zd bytes", thread->idx, recv_ret);

	return recv_ret;
}


static int handle_event_udp(struct epl_thread *thread,
			    struct srv_udp_state *state, int udp_fd)
{
	ssize_t recv_ret;
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(saddr);

	recv_ret = do_recvfrom(thread, udp_fd, &saddr, &saddr_len);
	if (unlikely(recv_ret <= 0))
		return (int)recv_ret;

	return _handle_event_udp(thread, state, &saddr);
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

	find = get_route_map(thread->state->ipv4_map, dst_addr);
	if (unlikely(find == -1))
		return -ENOENT;

	idx      = (uint16_t)find;
	dst_sess = &sess_arr[idx];
	send_ret = send_to_client(thread, dst_sess, &thread->pkt->srv, send_len);
	if (send_ret < 0)
		return (int)send_ret;

	return 0;
}


static int route_packet(struct epl_thread *thread, struct srv_udp_state *state,
			ssize_t len)
{
	int ret;
	ssize_t send_ret;
	size_t send_len, i;
	struct srv_pkt *srv_pkt = &thread->pkt->srv;
	struct udp_sess	*sess_arr = state->sess_arr;
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct iphdr *iphdr = &srv_pkt->tun_data.iphdr;

	send_len = srv_pprep(srv_pkt, TSRV_PKT_TUN_DATA, (uint16_t)len, 0);
	if (likely(iphdr->version == 4)) {
		ret = route_ipv4_packet(thread, ntohl(iphdr->daddr), sess_arr,
					send_len);
		if (ret != -ENOENT)
			return ret;
	}

	/*
	 * Broadcast this to all authenticated clients.
	 */
	for (i = 0; i < max_conn; i++) {
		struct udp_sess	*sess = &sess_arr[i];

		if (!sess->is_authenticated)
			continue;

		send_ret = send_to_client(thread, sess, srv_pkt, send_len);
		if (send_ret < 0)
			return (int)send_ret;
	}

	return 0;
}


static int handle_event_tun(struct epl_thread *thread,
			    struct srv_udp_state *state, int tun_fd)
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
	pr_debug("[thread=%hu] TUN read(%d, buf, %zu) = %zd bytes",
		 thread->idx, tun_fd, read_size, read_ret);

	return route_packet(thread, state, read_ret);
}


static int handle_event(struct epl_thread *thread, struct srv_udp_state *state,
			struct epoll_event *event)
{
	int ret = 0;
	int fd = event->data.fd;

	if (fd == thread->state->udp_fd) {
		ret = handle_event_udp(thread, state, fd);
	} else {
		ret = handle_event_tun(thread, state, fd);
	}

	return ret;
}


static int do_epoll_wait(struct epl_thread *thread, struct srv_udp_state *state)
{
	int ret, i, tmp;
	struct epoll_event *events;

	ret = _do_epoll_wait(thread);
	if (unlikely(ret < 0)) {
		pr_err("_do_epoll_wait(): " PRERF, PREAR(-ret));
		return ret;
	}

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = handle_event(thread, state, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}


static void thread_wait(struct epl_thread *thread, struct srv_udp_state *state)
{
	static _Atomic(bool) release_sub_thread = false;
	uint8_t nn = state->cfg->sys.thread_num;

	if (thread->idx != 0) {
		/*
		 * We are the sub thread.
		 * Waiting for the main thread be ready...
		 */
		while (!atomic_load(&release_sub_thread)) {
			if (unlikely(state->stop))
				return;

			usleep(100000);
		}
		return;
	}

	/*
	 * We are the main thread. Wait for all threads
	 * to be spawned properly.
	 */
	while (atomic_load(&state->n_on_threads) != nn) {

		prl_notice(2, "(thread=%u) "
			   "Waiting for subthread(s) to be ready...",
			   thread->idx);

		if (unlikely(state->stop))
			return;

		usleep(100000);
	}

	if (nn > 1)
		prl_notice(2, "All threads are ready!");

	prl_notice(2, "Initialization Sequence Completed");
	atomic_store(&release_sub_thread, true);
}


__no_inline static void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread;
	struct srv_udp_state *state;

	thread = (struct epl_thread *)thread_p;
	state  = thread->state;

	atomic_store(&thread->is_online, true);
	atomic_fetch_add(&state->n_on_threads, 1);
	thread_wait(thread, state);

	while (likely(!state->stop)) {
		ret = do_epoll_wait(thread, state);
		if (unlikely(ret)) {
			state->stop = true;
			break;
		}
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->n_on_threads, 1);
	return (void *)((intptr_t)ret);
}


static int spawn_thread(struct epl_thread *thread)
{
	int ret;

	prl_notice(2, "Spawning thread %u...", thread->idx);
	ret = pthread_create(&thread->thread, NULL, _run_event_loop, thread);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(thread->thread);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	return ret;
}


static int run_event_loop(struct srv_udp_state *state)
{
	int ret;
	void *ret_p;
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	atomic_store(&state->n_on_threads, 0);
	for (i = 1; i < nn; i++) {
		/*
		 * Spawn the subthreads.
		 * 
		 * For @i == 0, it is the main thread,
		 * don't spawn pthread for it.
		 */
		ret = spawn_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
out:
	return ret;
}


static bool wait_for_threads_to_exit(struct srv_udp_state *state)
{
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
		int ret;

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
		al64_free(threads[i].pkt);
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

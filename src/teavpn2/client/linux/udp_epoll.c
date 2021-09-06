// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/linux/udp.h>


static int epoll_add(int epoll_fd, int fd, uint32_t events, epoll_data_t data)
{
	int ret;
	struct epoll_event evt;

	memset(&evt, 0, sizeof(evt));
	evt.events = events;
	evt.data = data;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &evt);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d, events): " PRERF,
			epoll_fd, fd, PREAR(ret));
		ret = -ret;
	}

	return ret;
}


static int init_epoll_user_data(struct cli_udp_state *state)
{
	struct epld_struct *epl_udata, *udata;
	size_t i, nn = (size_t)state->cfg->sys.thread_num + 10u;

	epl_udata = calloc_wrp(nn, sizeof(*epl_udata));
	if (unlikely(!epl_udata))
		return -errno;

	for (i = 0; i < nn; i++) {
		udata = &epl_udata[i];
		udata->fd = -1;
		udata->type = 0;
		udata->idx = (uint16_t)i;
	}

	state->epl_udata = epl_udata;
	return 0;
}


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


static int register_fd_in_to_epoll(struct epl_thread *thread, int fd)
{
	epoll_data_t data;
	const uint32_t events = EPOLLIN | EPOLLPRI;
	int epoll_fd = thread->epoll_fd;

	memset(&data, 0, sizeof(data));
	data.fd = fd;
	prl_notice(4, "Registering fd (%d) to epoll (for thread %u)...",
		   fd, thread->idx);
	return epoll_add(epoll_fd, fd, events, data);
}


static int init_epoll_thread_data(struct cli_udp_state *state)
{
	int ret = 0;
	int *tun_fds = state->tun_fds;
	struct epl_thread *threads, *thread;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;

	state->epl_threads = NULL;
	threads = calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -errno;

	state->epl_threads = threads;

	/*
	 * Initialize all epoll_fd to -1 for graceful clean up in
	 * case we fail to create the epoll instance.
	 */
	for (i = 0; i < nn; i++) {
		threads[i].state = state;
		threads[i].epoll_fd = -1;
	}

	for (i = 0; i < nn; i++) {
		thread = &threads[i];
		thread->idx = i;

		ret = create_epoll_fd();
		if (unlikely(ret < 0))
			goto out;

		thread->epoll_fd = ret;

		if (i == 0) {
			/*
			 * Main thread is at index 0.
			 *
			 * Main thread is responsible to handle packet from UDP
			 * socket, decapsulate it and write it to tun_fd.
			 */
			ret = register_fd_in_to_epoll(thread, state->udp_fd);
		} else {
			ret = register_fd_in_to_epoll(thread, tun_fds[i]);
		}

		if (unlikely(ret))
			goto out;
	}


	if (nn == 1) {
		/*
		 * If we are single-threaded, the main thread is also
		 * responsible to read from TUN fd, encapsulate it and
		 * send it via UDP.
		 */
		ret = register_fd_in_to_epoll(&threads[0], tun_fds[0]);
	} else {
		/*
		 * If we are multithreaded, the subthread is responsible
		 * to read from tun_fds[0]. Don't give this work to the
		 * main thread for better concurrency.
		 */
		ret = register_fd_in_to_epoll(&threads[1], tun_fds[0]);
	}
out:
	return ret;
}


static void thread_wait(struct epl_thread *thread, struct cli_udp_state *state)
{
	static _Atomic(bool) release_sub_thread = false;
	uint8_t nn = (uint8_t)state->cfg->sys.thread_num;

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
	 * We are the main thread...
	 */
	while (atomic_load(&state->ready_thread) != nn) {
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


static ssize_t do_send_to(int udp_fd, const void *pkt, size_t send_len)
{
	int ret;
	ssize_t send_ret;
	send_ret = sendto(udp_fd, pkt, send_len, 0, NULL, 0);
	if (unlikely(send_ret < 0)) {
		ret = errno;
		pr_err("sendto(): " PRERF, PREAR(ret));
		return -ret;
	}
	if (unlikely((size_t)send_ret != send_len)) {
		pr_err("send_ret != send_len");
		return -EBADMSG;
	}
	pr_debug("sendto() %zd bytes", send_ret);
	return send_ret;
}


#if 0
static ssize_t do_recv_from(int udp_fd, void *pkt, size_t recv_len)
{
	int ret;
	ssize_t recv_ret;
	recv_ret = recvfrom(udp_fd, pkt, recv_len, 0, NULL, 0);
	if (unlikely(recv_ret < 0)) {
		ret = errno;
		pr_err("recvfrom(): " PRERF, PREAR(ret));
		return -ret;
	}
	pr_debug("recvfrom() %zd bytes", recv_ret);
	return recv_ret;
}
#endif


static int handle_tun_data(struct epl_thread *thread)
{
	uint16_t data_len;
	ssize_t write_ret;
	int tun_fd = thread->state->tun_fds[0];
	struct srv_pkt *srv_pkt = &thread->pkt.srv;

	data_len  = ntohs(srv_pkt->len);
	write_ret = write(tun_fd, srv_pkt->__raw, data_len);
	pr_debug("tun write, write_ret = %zd", write_ret);
	return write_ret < 0 ? -errno : 0;
}


static int _handle_event_udp(struct epl_thread *thread)
{
	struct srv_pkt *srv_pkt = &thread->pkt.srv;

	switch (srv_pkt->type) {
	case TSRV_PKT_HANDSHAKE:
	case TSRV_PKT_AUTH_OK:
		return 0;
	case TSRV_PKT_TUN_DATA:
		return handle_tun_data(thread);
	case TSRV_PKT_REQSYNC:
		return 0;
	case TSRV_PKT_SYNC:
		return 0;
	case TSRV_PKT_CLOSE:
	case TSRV_PKT_HANDSHAKE_REJECT:
	case TSRV_PKT_AUTH_REJECT:
		prl_notice(2, "Server has closed the connection!");
		return -EHOSTDOWN;
	}
	return 0;
}


static int handle_event_udp(int udp_fd, struct epl_thread *thread)
{
	int ret;
	ssize_t recv_ret;
	char *buf = thread->pkt.__raw;
	size_t recv_size = sizeof(thread->pkt.cli.__raw);

	recv_ret = recvfrom(udp_fd, buf, recv_size, 0, NULL, 0);
	if (unlikely(recv_ret <= 0)) {

		if (recv_ret == 0) {
			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		ret = errno;
		if (ret == EAGAIN)
			return 0;

		pr_err("recvfrom(udp_fd) (fd=%d): " PRERF, udp_fd, PREAR(ret));
		return -ret;
	}
	thread->pkt.len = (size_t)recv_ret;

	pr_debug("recvfrom() server %zd bytes", recv_ret);
	return _handle_event_udp(thread);
}


static int handle_event_tun(int tun_fd, struct epl_thread *thread)
{
	int ret;
	size_t send_len;
	ssize_t read_ret;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &thread->pkt.cli;

	read_ret = read(tun_fd, cli_pkt->__raw, sizeof(thread->pkt.cli.__raw));
	if (unlikely(read_ret < 0)) {
		ret = errno;
		if (likely(ret == EAGAIN))
			return 0;

		pr_err("read(tun_fd) (fd=%d): " PRERF, tun_fd, PREAR(ret));
		return -ret;
	}

	pr_debug("read() from tun_fd %zd bytes", read_ret);
	send_len = cli_pprep(cli_pkt, TCLI_PKT_TUN_DATA, (uint16_t)read_ret, 0);
	send_ret = do_send_to(thread->state->udp_fd, cli_pkt, send_len);
	return (send_ret < 0) ? (int)send_ret : 0;
}


/*
 * TL;DR
 * If this function returns non zero, TeaVPN2 process is exiting!
 *
 * -----------------------------------------------
 * This function should only return error code if
 * the error is fatal and need termination entire
 * process!
 *
 * If the error is not fatal, this function must
 * return 0.
 *
 */
static int handle_event(struct epl_thread *thread, struct epoll_event *evt)
{
	int ret = 0;
	int fd = evt->data.fd;

	if (fd == thread->state->udp_fd) {
		ret = handle_event_udp(fd, thread);
	} else {
		/* It's a TUN fd. */
		ret = handle_event_tun(fd, thread);
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


static int send_ping_packet(struct epl_thread *thread)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &thread->pkt.cli;
	send_len = cli_pprep(cli_pkt, TCLI_PKT_PING, 0, 0);
	send_ret = do_send_to(thread->state->udp_fd, cli_pkt, send_len);
	return (send_ret < 0) ? (int)send_ret : 0;
}


static int send_close_packet(struct epl_thread *thread)
{
	int i;
	size_t send_len;
	struct cli_pkt *cli_pkt = &thread->pkt.cli;

	prl_notice(2, "Sending close packet to server...");
	send_len = cli_pprep(cli_pkt, TCLI_PKT_CLOSE, 0, 0);
	for (i = 0; i < 5; i++)
		do_send_to(thread->state->udp_fd, cli_pkt, send_len);

	return 0;
}


static int do_epoll_wait(struct epl_thread *thread)
{
	int ret, i, tmp;
	struct epoll_event *events;

	ret = _do_epoll_wait(thread);
	if (unlikely(ret < 0)) {
		pr_err("_do_epoll_wait(): " PRERF, PREAR(-ret));
		return ret;
	}

	if (ret == 0)
		return send_ping_packet(thread);

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = handle_event(thread, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}


static void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread = (struct epl_thread *)thread_p;
	struct cli_udp_state *state = thread->state;

	atomic_store(&thread->is_online, true);
	atomic_fetch_add(&state->ready_thread, 1);
	thread_wait(thread, state);

	state = thread->state;
	thread->epoll_timeout = 5000;
	while (likely(!state->stop)) {
		ret = do_epoll_wait(thread);
		if (unlikely(ret))
			break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->ready_thread, 1);
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


static int run_event_loop(struct cli_udp_state *state)
{
	int ret = 0;
	void *ret_p;
	struct epl_thread *threads = state->epl_threads;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;

	for (i = 1; i < nn; i++) {
		ret = spawn_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
	send_close_packet(&threads[0]);
out:
	return ret;
}


static void close_epoll_fds(struct epl_thread *threads, uint8_t nn)
{
	uint8_t i;
	struct epl_thread *thread;
	for (i = 0; i < nn; i++) {
		int epoll_fd;
		thread = &threads[i];

		epoll_fd = thread->epoll_fd;
		if (epoll_fd == -1)
			continue;

		close(epoll_fd);
		prl_notice(2, "Closing threads[%hhu].epoll_fd (fd=%d)", i,
			   epoll_fd);
	}
}


static bool wait_for_threads_to_exit(struct cli_udp_state *state)
{
	unsigned wait_c = 0;
	uint16_t thread_on = 0, cc;
	uint8_t nn, i;
	struct epl_thread *threads;

	thread_on = atomic_load(&state->ready_thread);
	if (thread_on == 0)
		return true;

	threads = state->epl_threads;
	nn = (uint8_t)state->cfg->sys.thread_num;
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
	while ((cc = atomic_load(&state->ready_thread)) > 0) {

		if (cc != thread_on) {
			thread_on = cc;
			prl_notice(2, "Waiting for %hu thread(s) to exit...", cc);
		}

		usleep(100000);
		if (wait_c++ > 1000)
			return false;
	}
	return true;
}


static void destroy_epoll(struct cli_udp_state *state)
{
	struct epl_thread *threads;
	uint8_t nn = (uint8_t)state->cfg->sys.thread_num;

	if (!wait_for_threads_to_exit(state)) {
		/* Thread(s) won't exit, don't free the heap! */
		pr_emerg("Thread(s) won't exit!");
		state->threads_wont_exit = true;
		return;
	}

	threads = state->epl_threads;
	if (threads) {
		close_epoll_fds(threads, nn);
		al64_free(threads);
	}
	al64_free(state->epl_udata);
}


int teavpn2_udp_client_epoll(struct cli_udp_state *state)
{
	int ret;

	ret = init_epoll_user_data(state);
	if (unlikely(ret))
		goto out;

	ret = init_epoll_thread_data(state);
	if (unlikely(ret))
		goto out;

	state->stop = false;
	ret = run_event_loop(state);
out:
	destroy_epoll(state);
	return ret;
}

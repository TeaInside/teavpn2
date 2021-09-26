// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/linux/udp.h>


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


static int do_epoll_fd_registration(struct cli_udp_state *state,
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


static int init_epoll_thread(struct cli_udp_state *state,
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


static int init_epoll_thread_array(struct cli_udp_state *state)
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

		pkt = al4096_malloc_mmap(sizeof(*pkt));
		if (unlikely(!pkt))
			return -errno;

		threads[i].pkt = pkt;
	}

	return ret;
}


static ssize_t _do_send_to(int udp_fd, const void *pkt, size_t send_len)
{
	int ret;
	ssize_t send_ret;
	send_ret = sendto(udp_fd, pkt, send_len, 0, NULL, 0);
	if (unlikely(send_ret < 0)) {
		ret = errno;
		pr_err("sendto(): " PRERF, PREAR(ret));
		return (ssize_t)-ret;
	}
	return send_ret;
}


static ssize_t _do_recv_from(int udp_fd, void *pkt, size_t recv_len)
{
	int ret;
	ssize_t recv_ret;
	recv_ret = recvfrom(udp_fd, pkt, recv_len, 0, NULL, 0);
	if (unlikely(recv_ret < 0)) {
		ret = errno;
		pr_err("recvfrom(): " PRERF, PREAR(ret));
		return (ssize_t)-ret;
	}
	return recv_ret;
}


static ssize_t do_send_to(struct epl_thread *thread, const void *buf,
			  size_t pkt_len)
{
	int udp_fd = thread->state->udp_fd;
	ssize_t send_ret = _do_send_to(udp_fd, buf, pkt_len);
	pr_debug("[thread=%hu] sendto(udp_fd=%d) %zd bytes", thread->idx,
		 udp_fd, send_ret);
	return send_ret;
}


static ssize_t do_recv_from(struct epl_thread *thread, void *buf, size_t len)
{
	int udp_fd = thread->state->udp_fd;
	ssize_t recv_ret = _do_recv_from(udp_fd, buf, len);
	pr_debug("[thread=%hu] recvfrom(udp_fd=%d) %zd bytes", thread->idx,
		 udp_fd, recv_ret);
	return recv_ret;
}


static ssize_t recv_from_server(struct epl_thread *thread, int udp_fd)
{
	int ret;
	ssize_t recv_ret;
	char *buf = thread->pkt->__raw;
	const size_t recv_size = sizeof(thread->pkt->cli.__raw);

	recv_ret = do_recv_from(thread, buf, recv_size);
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
	return recv_ret;
}


static int handle_tun_data(struct epl_thread *thread)
{
	uint16_t data_len;
	ssize_t write_ret;
	int tun_fd = thread->state->tun_fds[0];
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	data_len  = ntohs(srv_pkt->len);
	write_ret = write(tun_fd, srv_pkt->__raw, data_len);
	pr_debug("[thread=%hu] write(tun_fd=%d) %zd bytes", thread->idx, tun_fd,
		 write_ret);
	return write_ret < 0 ? -errno : 0;
}


static int handle_req_sync(struct epl_thread *thread)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &thread->pkt->cli;

	send_len = cli_pprep(cli_pkt, TSRV_PKT_SYNC, 0, 0);
	send_ret = do_send_to(thread, cli_pkt, send_len);
	return unlikely(send_ret < 0) ? (int)send_ret : 0;
}


static int _handle_event_udp(struct epl_thread *thread,
			     struct cli_udp_state *state)
{
	struct srv_pkt *srv_pkt = &thread->pkt->srv;

	switch (srv_pkt->type) {
	case TSRV_PKT_HANDSHAKE:
	case TSRV_PKT_AUTH_OK:
		return 0;
	case TSRV_PKT_TUN_DATA:
		return handle_tun_data(thread);
	case TSRV_PKT_REQSYNC:
		get_unix_time(&thread->state->last_t);
		return handle_req_sync(thread);
	case TSRV_PKT_SYNC:
		get_unix_time(&thread->state->last_t);
		return 0;
	case TSRV_PKT_CLOSE:
		state->stop = true;
		return 0;
	default:
		/* Bad packet! */
		return -EBADRQC;
	}
}


static int handle_event_udp(struct epl_thread *thread,
			    struct cli_udp_state *state, int udp_fd)
{
	ssize_t recv_ret;

	recv_ret = recv_from_server(thread, udp_fd);
	if (unlikely(recv_ret <= 0))
		return (int)recv_ret;

	return _handle_event_udp(thread, state);
}


static int handle_event_tun(struct epl_thread *thread, int tun_fd)
{
	int ret;
	size_t send_len;
	ssize_t read_ret;
	ssize_t send_ret;
	struct cli_pkt *cli_pkt = &thread->pkt->cli;

	read_ret = read(tun_fd, cli_pkt->__raw, sizeof(thread->pkt->cli.__raw));
	if (unlikely(read_ret < 0)) {
		ret = errno;
		if (likely(ret == EAGAIN))
			return 0;

		pr_err("read(tun_fd) (fd=%d): " PRERF, tun_fd, PREAR(ret));
		return -ret;
	}

	pr_debug("[thread=%hu] read(tun_fd=%d) %zd bytes", thread->idx, tun_fd,
		 read_ret);

	send_len = cli_pprep(cli_pkt, TCLI_PKT_TUN_DATA, (uint16_t)read_ret, 0);
	send_ret = do_send_to(thread, cli_pkt, send_len);
	return (send_ret < 0) ? (int)send_ret : 0;
}


static int handle_event(struct epl_thread *thread, struct cli_udp_state *state,
			struct epoll_event *event)
{
	int ret = 0;
	int fd = event->data.fd;

	if (fd == thread->state->udp_fd)
		ret = handle_event_udp(thread, state, fd);
	else
		ret = handle_event_tun(thread, fd);

	if ((state->loop_c++ % UDP_LOOP_C_DEADLINE) == 0)
		get_unix_time(&state->last_t);

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


static int do_epoll_wait(struct epl_thread *thread, struct cli_udp_state *state)
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


static void thread_wait(struct epl_thread *thread, struct cli_udp_state *state)
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


static noinline void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread;
	struct cli_udp_state *state;

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


static void tt_send_reqsync(struct cli_udp_state *state)
{
	size_t send_len;
	struct cli_pkt pkt;
	int udp_fd = state->udp_fd;
	ssize_t __maybe_unused send_ret;

	send_len = cli_pprep(&pkt, TCLI_PKT_REQSYNC, 0, 0);
	send_ret = _do_send_to(udp_fd, &pkt, send_len);
	pr_debug("[timer] sendto(udp_fd=%d) %zd bytes", udp_fd, send_ret);
}


static void _run_timer_thread(struct cli_udp_state *state)
{
	time_t time_diff = 0;
	const time_t max_diff = UDP_SESS_TIMEOUT;

	get_unix_time(&time_diff);
	time_diff -= state->last_t;

	if (time_diff > max_diff) {
		prl_notice(2, "UDP timer timedout");
		prl_notice(2, "Stopping...");
		state->timeout_disconnect = true;
		state->stop = true;
		return;
	}

	if (time_diff > ((max_diff * 3) / 4))
		tt_send_reqsync(state);
}


static void *run_timer_thread(void *arg)
{
	struct cli_udp_state *state = (struct cli_udp_state *)arg;

	if (nice(40) < 0) {
		int err = errno;
		pr_warn("nice(40) = " PRERF, PREAR(err));
	}

	atomic_store(&state->tt.is_online, true);
	state->timeout_disconnect = false;
	while (likely(!state->stop)) {
		sleep(3);
		_run_timer_thread(state);
	}
	atomic_store(&state->tt.is_online, false);
	return NULL;
}


static int spawn_timer_thread(struct cli_udp_state *state)
{
	int ret;
	pthread_t *tt = &state->tt.thread;

	prl_notice(2, "Spawning timer thread...");
	ret = pthread_create(tt, NULL, run_timer_thread, state);
	if (unlikely(ret)) {
		pr_err("pthread_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	ret = pthread_detach(*tt);
	if (unlikely(ret)) {
		pr_err("pthread_detach(): " PRERF, PREAR(ret));
		return -ret;
	}

	pthread_setname_np(*tt, "timer");
	return ret;
}


static int run_event_loop(struct cli_udp_state *state)
{
	int ret;
	void *ret_p;
	uint8_t i, nn = state->cfg->sys.thread_num;
	struct epl_thread *threads = state->epl_threads;

	ret = spawn_timer_thread(state);
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
		ret = spawn_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
out:
	return ret;
}


static bool wait_for_threads_to_exit(struct cli_udp_state *state)
{
	int ret;
	unsigned wait_c = 0;
	uint16_t thread_on = 0, cc;
	uint8_t nn, i;
	struct epl_thread *threads;

	if (atomic_load(&state->tt.is_online)) {
		ret = pthread_kill(state->tt.thread, SIGTERM);
		if (unlikely(ret)) {
			pr_err("pthread_kill(state->tt.thread, SIGTERM): "
			       PRERF, PREAR(ret));
		}

		prl_notice(2, "Waiting for timer thread to exit...");

		while (atomic_load(&state->tt.is_online)) {
			usleep(100000);
			if (wait_c++ > 1000)
				return false;
		}
		wait_c = 0;
	}


	thread_on = atomic_load(&state->n_on_threads);
	if (thread_on == 0)
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
			prl_notice(2, "Waiting for %hu thread(s) to exit...", cc);
		}

		usleep(100000);
		if (wait_c++ > 1000)
			return false;
	}
	return true;
}


static void close_epoll_fds(struct epl_thread *threads, uint8_t nn)
{
	uint8_t i;
	struct epl_thread *thread;

	if (!threads)
		return;

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


static void destroy_epoll(struct cli_udp_state *state)
{
	struct epl_thread *threads;
	uint8_t i, nn = state->cfg->sys.thread_num;

	if (!wait_for_threads_to_exit(state)) {
		/* Thread(s) won't exit, don't free the heap! */
		pr_emerg("Thread(s) won't exit!");
		state->threads_wont_exit = true;
		return;
	}

	threads = state->epl_threads;
	if (threads) {
		close_epoll_fds(threads, nn);
		for (i = 0; i < nn; i++)
			al4096_free_munmap(threads[i].pkt, sizeof(*threads[i].pkt));
	}
	al64_free(threads);
}


int teavpn2_udp_client_epoll(struct cli_udp_state *state)
{
	int ret;

	ret = init_epoll_thread_array(state);
	if (unlikely(ret))
		goto out;

	state->stop = false;
	get_unix_time(&state->last_t);
	ret = run_event_loop(state);
out:
	destroy_epoll(state);
	return ret;
}

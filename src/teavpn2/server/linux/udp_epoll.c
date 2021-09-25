// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

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

		pkt = calloc_wrp(1ul, sizeof(*pkt));
		if (unlikely(!pkt))
			return -errno;

		threads[i].pkt = pkt;
	}

	return 0;
}


static __no_inline void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread;
	struct srv_udp_state *state;

	thread = (struct epl_thread *)thread_p;
	state  = thread->state;

	atomic_store(&thread->is_online, true);
	atomic_fetch_add(&state->n_on_threads, 1);

	while (likely(!state->stop)) {
		sleep(2);
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->n_on_threads, 1);
	return (void *)((intptr_t)ret);
}


static void zombie_reaper_do_scan(struct srv_udp_state *state)
{
	uint16_t i, j, max_conn = state->cfg->sock.max_conn;
	struct udp_sess *sess, *sess_arr = state->sess_arr;

	for (i = j = 0; i < max_conn; i++) {
		time_t time_diff = 0;

		sess = &sess_arr[i];
		if (!sess->is_connected)
			continue;

		get_unix_time(&time_diff);
		time_diff -= sess->last_act;

		// if (sess->is_authenticated)
		// 	zr_chk_auth(state, sess, time_diff);
		// else
		// 	zr_chk_no_auth(state, sess, time_diff);
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
		pr_debug("[zombie reaper] Scanning...");
		zombie_reaper_do_scan(state);
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

		if (!sess_arr[i].is_connected)
			continue;

		// close_udp_session(&state->epl_threads[0], &sess_arr[i]);
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

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <unistd.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/linux/udp.h>


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


static int epoll_delete(int epoll_fd, int fd)
{
	int ret;

	ret = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("epoll_ctl(%d, EPOLL_CTL_ADD, %d, events): " PRERF,
			epoll_fd, fd, PREAR(ret));
		ret = -ret;
	}

	return ret;
}


static int init_epoll_user_data(struct srv_udp_state *state)
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


static int init_epoll_thread_data(struct srv_udp_state *state)
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


static int handle_event_udp(int udp_fd, struct epl_thread *thread)
{
	int ret;
	ssize_t recv_ret;
	struct sockaddr_in addr;
	char *buf = thread->pkt.cli.__raw;
	socklen_t addrlen = sizeof(addr);
	size_t recv_size = sizeof(thread->pkt.cli.__raw);

	recv_ret = recvfrom(udp_fd, buf, recv_size, 0, (struct sockaddr *)&addr,
			    &addrlen);
	if (unlikely(recv_ret <= 0)) {

		if (recv_ret == 0) {
			pr_err("UDP socket disconnected!");
			return -ENETDOWN;
		}

		ret = errno;
		if (likely(ret == EAGAIN))
			return 0;

		pr_err("recvfrom(udp_fd) (fd=%d): " PRERF, udp_fd, PREAR(ret));
		return -ret;
	}
	thread->pkt.len = (size_t)recv_ret;

	pr_debug("recvfrom() client %zd bytes", recv_ret);
	return 0;
}


static int handle_event_tun(int tun_fd, struct epl_thread *thread)
{
	int ret;
	ssize_t read_ret;
	char *buf = thread->pkt.srv.__raw;
	size_t read_size = sizeof(thread->pkt.srv.__raw);

	read_ret = read(tun_fd, buf, read_size);
	if (unlikely(read_ret < 0)) {
		ret = errno;
		if (likely(ret == EAGAIN))
			return 0;

		pr_err("read(tun_fd) (fd=%d): " PRERF, tun_fd, PREAR(ret));
		return -ret;
	}
	thread->pkt.len = (size_t)read_ret;

	pr_debug("read() from tun_fd %zd bytes", read_ret);
	return 0;
}



/*
 * TL;DR
 * If this function returns non zero, TeaVPN2 process is exiting!
 *
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
		/*
		 * It's a TUN fd.
		 */
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
			prl_notice(2, "Interrupted!");
			return 0;
		}

		pr_err("epoll_wait(): " PRERF, PREAR(ret));
		return -ret;
	}

	return ret;
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

	pr_debug("_do_epoll_wait(): %d (thread=%u)", ret, thread->idx);

	events = thread->events;
	for (i = 0; i < ret; i++) {
		tmp = handle_event(thread, &events[i]);
		if (unlikely(tmp))
			return tmp;
	}

	return 0;
}


static void thread_wait_or_add_counter(struct epl_thread *thread,
				       struct srv_udp_state *state)
{
	uint8_t nn;

	atomic_fetch_add(&state->ready_thread, 1);
	if (thread->idx != 0)
		return;

	/*
	 * We are the main thread...
	 */
	nn = (uint8_t)state->cfg->sys.thread_num;
	while (atomic_load(&state->ready_thread) != nn) {
		prl_notice(2, "Waiting for subthread(s) to be ready...");
		if (unlikely(state->stop))
			return;
		sleep(1);
	}

	if (nn > 1)
		prl_notice(2, "All threads all are ready!");

	prl_notice(2, "Initialization Sequence Completed");
}


static void *_run_event_loop(void *thread_p)
{
	int ret = 0;
	struct epl_thread *thread = (struct epl_thread *)thread_p;
	struct srv_udp_state *state = thread->state;

	thread_wait_or_add_counter(thread, state);
	thread->epoll_timeout = 1000;

	while (likely(!state->stop)) {
		ret = do_epoll_wait(thread);
		if (unlikely(ret))
			break;
	}

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
	void *ret_p;
	int ret = 0;
	struct epl_thread *threads = state->epl_threads;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;


	atomic_store(&state->ready_thread, 0);
	for (i = 1; i < nn; i++) {
		ret = spawn_thread(&threads[i]);
		if (unlikely(ret))
			goto out;
	}

	/*
	 * ret_p is just to shut the clang warning up!
	 */
	ret_p = _run_event_loop(&threads[0]);
	ret   = (int)((intptr_t)ret_p);
out:
	return ret;
}

static void destroy_epoll(struct srv_udp_state *state)
{
	struct epl_thread *threads;
	uint8_t nn = (uint8_t)state->cfg->sys.thread_num;

	threads = state->epl_threads;
	if (threads) {
		close_epoll_fds(threads, nn);
		al64_free(threads);
	}
	al64_free(state->epl_udata);
}


int teavpn2_udp_server_epoll(struct srv_udp_state *state)
{
	int ret = 0;

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

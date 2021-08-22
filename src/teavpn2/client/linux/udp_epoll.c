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


static int init_epoll(struct epl_thread *thread)
{
	int ret = 0;
	int epoll_fd;

	epoll_fd = epoll_create(255);
	if (unlikely(epoll_fd < 0)) {
		ret = errno;
		pr_err("epoll_create(): " PRERF, PREAR(ret));
		return -ret;
	}

	thread->epoll_fd = epoll_fd;
	return 0;
}


static int register_thread_tun_fd(struct epl_thread *thread)
{
	epoll_data_t data;
	const uint32_t events = EPOLLIN | EPOLLPRI;
	int tun_fd = thread->state->tun_fds[thread->idx];
	int epoll_fd = thread->epoll_fd;

	data.u64 = EPLD_DATA_TUN;
	prl_notice(4, "Registering tun_fd (%d) to epoll (for thread %u)...",
		   tun_fd, thread->idx);
	return epoll_add(epoll_fd, tun_fd, events, data);
}


static int register_thread_udp_fd(struct epl_thread *thread)
{
	epoll_data_t data;
	const uint32_t events = EPOLLIN | EPOLLPRI;
	int udp_fd = thread->state->udp_fd;
	int epoll_fd = thread->epoll_fd;

	data.u64 = EPLD_DATA_UDP;
	prl_notice(4, "Registering udp_fd (%d) to epoll (for thread %u)...",
		   udp_fd, thread->idx);
	return epoll_add(epoll_fd, udp_fd, events, data);
}


static int init_epoll_thread_data(struct cli_udp_state *state)
{
	int ret = 0;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	struct epl_thread *threads, *thread;

	state->epl_threads = NULL;
	threads = calloc_wrp(nn, sizeof(*threads));
	if (unlikely(!threads))
		return -errno;

	state->epl_threads = threads;

	/*
	 * Initialize all epoll_fd to -1. The reason is that
	 * we are going to have a cleaner which does this check:
	 *
	 *     if (the_fd != -1) {
	 *       // We need a clean up, because the fd is valid.
	 *     }
	 */
	for (i = 0; i < nn; i++)
		threads[i].epoll_fd = -1;

	for (i = 0; i < nn; i++) {
		thread = &threads[i];
		thread->state = state;
		thread->idx   = i;
	
		ret = init_epoll(thread);
		if (unlikely(ret))
			goto out;

		ret = register_thread_tun_fd(thread);
		if (unlikely(ret))
			goto out;

		/*
		 * Main thread is responsible to handle
		 * data from the server.
		 */
		if (unlikely(i == 0)) {
			ret = register_thread_udp_fd(thread);
			if (unlikely(ret))
				goto out;
		}
	}

out:
	return ret;
}


static void close_epoll_fds(struct epl_thread *threads, uint8_t nn)
{
	uint8_t i;
	struct epl_thread *thread;
	for (i = 0; i < nn; i++) {
		thread = &threads[i];
		if (thread->epoll_fd != -1) {
			close(thread->epoll_fd);
			prl_notice(2, "Closing threads[%hhu].epoll_fd (fd=%d)",
				   i, thread->epoll_fd);
		}
	}
}


static void destroy_epoll(struct cli_udp_state *state)
{
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	struct epl_thread *threads;

	threads = state->epl_threads;
	if (threads) {
		close_epoll_fds(threads, nn);
		al64_free(threads);
	}
	al64_free(state->epl_udata);
}


int teavpn2_udp_epoll(struct cli_udp_state *state)
{
	int ret;

	ret = init_epoll_user_data(state);
	if (unlikely(ret))
		goto out;

	ret = init_epoll_thread_data(state);
	if (unlikely(ret))
		goto out;

out:
	destroy_epoll(state);
	return ret;
}

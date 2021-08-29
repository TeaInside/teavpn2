// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp_io_uring.c
 *
 *  TeaVPN2 client core for Linux (io_uring support).
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "tcp_common.h"



static int send_init_handshake(struct cli_thread *thread)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_state *state = thread->state;
	struct tcli_pkt *cli_pkt = &state->cpkt;
	struct tcli_pkt_handshake *pkt_hs = &cli_pkt->handshake;

	pkt_hs->need_encryption = false;
	pkt_hs->has_min = false;
	pkt_hs->has_max = false;
	pkt_hs->cur.ver = VERSION;
	pkt_hs->cur.patch_lvl = PATCHLEVEL;
	pkt_hs->cur.sub_lvl = SUBLEVEL;
	sane_strncpy(pkt_hs->cur.extra, EXTRAVERSION, sizeof(pkt_hs->cur.extra));

	cli_pkt->type = TCLI_PKT_HANDSHAKE;
	cli_pkt->pad_len = 0u;
	cli_pkt->length = sizeof(*pkt_hs);
	send_len = TCLI_PKT_MIN_READ + sizeof(*pkt_hs);

	send_ret = send(state->tcp_fd, cli_pkt, send_len, 0);
	if (unlikely(send_ret < 0)) {
		int err = errno;
		pr_err("send(): " PRERF, PREAR(err));
		return -err;
	}

	if (unlikely(((size_t)send_ret) != send_len)) {
		pr_err("send_ret != send_len");
		pr_err("send_ret = %zd", send_ret);
		pr_err("send_len = %zu", send_len);
		pr_err("Cannot initialize handshake with server");
		return -EAGAIN;
	}

	pr_notice("Handshake packet sent! (%zd bytes)", send_ret);
	pr_notice("Waiting for server response...");
	return 0;
}


static int do_uring_wait(struct cli_thread *thread, struct io_uring_cqe **cqe_p)
{
	int ret;
	struct __kernel_timespec *timeout = &thread->ring_timeout;

	ret = io_uring_wait_cqe_timeout(&thread->ring, cqe_p, timeout);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME)) {
		timeout->tv_sec = 1;
		return ret;
	}

	if (unlikely(ret == -EINTR)) {
		pr_notice("Interrupted (thread=%u)", thread->idx);
		return 0;
	}

	pr_err("io_uring_wait_cqe(): " PRERF, PREAR(-ret));
	return -ret;
}


static int handle_event_tcp(struct cli_thread *thread, struct io_uring_cqe *cqe)
{
	pr_notice("test");
}


static int handle_event(struct cli_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0;
	void *fret;
	uintptr_t type;


	if (unlikely(!cqe))
		return 0;


	/*
	 * `fret` is just to shut the clang up!
	 */
	fret = io_uring_cqe_get_data(cqe);
	type = (uintptr_t)fret;
	switch (type) {
	case RING_QUE_NOP:
		io_uring_cqe_seen(&thread->ring, cqe);
		return 0;
	case RING_QUE_TCP:
		ret = handle_event_tcp(thread, cqe);
		break;
	case RING_QUE_TUN:
		// ret = handle_event_tun(thread, cqe);
		break;
	default:
		// ret = handle_event_client(thread, cqe);
		break;
	}

	return ret;
}


static __no_inline void *run_thread(void *_thread)
{
	intptr_t ret = 0;
	struct io_uring_cqe *cqe;
	struct cli_thread *thread = _thread;
	struct cli_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	// teavpn2_server_tcp_wait_threads(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {
		cqe = NULL;
		ret = do_uring_wait(thread, &cqe);
		if (likely(!ret)) {
			ret = handle_event(thread, cqe);
			if (unlikely(ret))
				break;
		} else {
			if (unlikely(ret == -ETIME))
				continue;
			break;
		}
	}

	if (thread->idx > 0)
		pr_notice("Thread %u is exiting...", thread->idx);

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	return (void *)ret;
}


static int spawn_threads(struct cli_state *state)
{
	size_t i;
	unsigned en_num; /* Number of queue entries */
	size_t nn = state->cfg->sys.thread;
	int ret = 0, *tun_fds = state->tun_fds;
	struct cli_thread *threads = state->threads;

	if (nn > 1)
		pr_notice("Spawning threads...");

	/*
	 * Distribute tun_fds to all threads. So each thread has
	 * its own tun_fds for writing.
	 */
	en_num = 3000u + (state->cfg->sys.thread * 100u);
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		struct io_uring_sqe *sqe;
		struct cli_thread *thread;
		struct io_uring *ring;

		thread         = &threads[i];
		ring           = &thread->ring;
		thread->tun_fd = tun_fd;

		ret = io_uring_queue_init(en_num, ring, 0);
		if (unlikely(ret)) {
			pr_err("io_uring_queue_init(): " PRERF, PREAR(-ret));
			break;
		}
		thread->ring_init = true;


		sqe = io_uring_get_sqe(ring);
		if (unlikely(!sqe)) {
			pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
			ret = -ENOMEM;
			break;
		}

		io_uring_prep_read(sqe, tun_fd, thread->spkt.raw_buf,
				   sizeof(thread->spkt.raw_buf), 0);
		io_uring_sqe_set_data(sqe, UPTR(RING_QUE_TUN));

		/*
		 * Don't spawn a thread for `i == 0`,
		 * because we are going to run it on
		 * the main thread.
		 */
		if (unlikely(i == 0))
			continue;


		ret = io_uring_submit(ring);
		if (unlikely(ret < 0)) {
			pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
			break;
		}


		ret = pthread_create(&thread->thread, NULL, run_thread, thread);
		if (unlikely(ret)) {
			pr_err("pthread_create(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}


		ret = pthread_detach(thread->thread);
		if (unlikely(ret)) {
			pr_err("pthread_detach(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}
	}
	return ret;
}


int teavpn2_client_tcp_run_io_uring(struct cli_state *state)
{
	int ret;
	struct cli_thread *thread;
	struct io_uring_sqe *sqe;

	ret = spawn_threads(state);
	if (unlikely(ret))
		goto out;

	pr_notice("Initializing protocol handshake with server...");
	thread = &state->threads[0];
	ret = send_init_handshake(thread);
	if (unlikely(ret))
		goto out;


	/*
	 * Main thread is responsible to accept
	 * new connections, so we add tcp_fd to
	 * its uring queue resource.
	 */
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
		ret = -ENOMEM;
		goto out;
	}

	io_uring_prep_recv(sqe, state->tcp_fd, state->raw_pkt,
			   sizeof(state->raw_pkt), MSG_WAITALL);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_TCP));

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out;
	}

	/*
	 * Run the main thread!
	 *
	 * `fret` is just to shut the clang up!
	 */
	{
		void *fret;
		fret = run_thread(thread);
		ret  = (int)((intptr_t)fret);
	}
out:
	return ret;
}

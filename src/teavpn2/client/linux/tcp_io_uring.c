// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp_io_uring.c
 *
 *  TeaVPN2 client core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "./tcp_common.h"


static int init_iou_cqe_vec(struct iou_cqe_vec **cqe_vec_p)
{
	struct iou_cqe_vec *cqe_vec;

	cqe_vec = al64_malloc(IOUCL_VEC_NUM * sizeof(*cqe_vec));
	if (unlikely(!cqe_vec))
		return -ENOMEM;

	*cqe_vec_p = cqe_vec;
	return 0;
}


static void *run_thread(void *thread_p)
{
	struct cli_thread *thread = thread_p;
	return NULL;
}


static int init_threads(struct cli_state *state)
{
	int ret = 0;
	struct cli_thread *threads;
	size_t i, nn = state->cfg->sys.thread;
	struct io_uring_params ring_params;
	const unsigned ring_flags = IORING_SETUP_CLAMP | IORING_SETUP_SQPOLL;

	threads = state->threads;

	for (i = 0; i < nn; i++) {
		struct io_uring_sqe *sqe;
		int tun_fd = state->tun_fds[i];
		struct cli_thread *thread = &threads[i];
		struct io_uring *ring = &thread->ring;
		void *tun_buf = thread->cpkt.raw_buf;
		unsigned int tun_buf_size = sizeof(thread->cpkt.raw_buf);

		ret = tv_stack_init(&thread->ioucl_stk, IOUCL_VEC_NUM);
		if (unlikely(ret))
			break;

		ret = init_iou_cqe_vec(&thread->cqe_vec);
		if (unlikely(ret))
			break;

		memset(&ring_params, 0, sizeof(ring_params));
		ring_params.flags = ring_flags;

		ret = io_uring_queue_init_params(1u << 20u, ring, &ring_params);
		if (unlikely(ret))
			break;

		thread->ring_init = true;
		thread->tun_fd = tun_fd;
		thread->state  = state;
		thread->idx    = (uint16_t)i;
		thread->read_s = 0;
		thread->ring_timeout.tv_sec = 10;

		sqe = io_uring_get_sqe(ring);
		if (unlikely(!sqe)) {
			pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
			ret = -ENOMEM;
			break;
		}

		io_uring_prep_read(sqe, tun_fd, tun_buf, tun_buf_size, 0);
		io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TUN_READ));

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


int teavpn2_client_tcp_event_loop_io_uring(struct cli_state *state)
{
	int ret = 0;

	ret = init_threads(state);
	if (unlikely(ret)) {
		pr_err("init_threads(): " PRERF, PREAR(-ret));
		goto out;
	}


out:
	return ret;
}

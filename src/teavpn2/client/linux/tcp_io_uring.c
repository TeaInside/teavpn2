// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/linux/tcp_io_uring.c
 *
 *  TeaVPN2 client core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
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


static int do_iou_write(struct cli_thread *thread, int fd,
			struct iou_cqe_vec *cqev, int flags)
{
	int ret;
	struct io_uring_sqe *sqe;
	struct io_uring *ring = &thread->ring;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe))
		return -EAGAIN;

	io_uring_prep_write(sqe, fd, cqev->raw_pkt, (unsigned)cqev->len, flags);
	io_uring_sqe_set_data(sqe, cqev);

	ret = io_uring_submit(ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		return ret;
	}
	return 0;
}


static int do_iou_send(struct cli_thread *thread, int fd,
		       struct iou_cqe_vec *cqev, int flags)
{
	int ret;
	struct io_uring_sqe *sqe;
	struct io_uring *ring = &thread->ring;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe))
		return -EAGAIN;

	io_uring_prep_send(sqe, fd, cqev->raw_pkt, (unsigned)cqev->len, flags);
	io_uring_sqe_set_data(sqe, cqev);

	ret = io_uring_submit(ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		return ret;
	}
	return 0;
}


static struct iou_cqe_vec *get_iou_cqe_vec(struct cli_thread *thread)
{
	int32_t idx;
	struct iou_cqe_vec *cqev;
	struct tv_stack	*ioucl_stk = &thread->ioucl_stk;

	bt_mutex_lock(&ioucl_stk->lock);
	idx = tv_stack_pop(ioucl_stk);
	bt_mutex_unlock(&ioucl_stk->lock);
	if (unlikely(idx == -1))
		return NULL;

	cqev = &thread->cqe_vec[idx];
	cqev->idx = (uint16_t)idx;
	cqev->vec_type = IOU_CQE_VEC_NOP;
	return cqev;
}


static void put_iou_cqe_vec(struct cli_thread *thread, struct iou_cqe_vec *cqev)
{
	int32_t idx;
	struct tv_stack	*ioucl_stk = &thread->ioucl_stk;

	bt_mutex_lock(&ioucl_stk->lock);
	idx = tv_stack_push(ioucl_stk, cqev->idx);
	bt_mutex_unlock(&ioucl_stk->lock);
	if (likely(idx != -1))
		return;

	panic("Wrong logic: Attempted to push to ioucl_stk when it is full "
	      "(thread=%u)", thread->idx);
}


static int rearm_io_uring_read_tun(struct cli_thread *thread)
{
	int ret;
	struct io_uring_sqe *sqe;
	void *tun_buf = &thread->cpkt.iface_data;
	unsigned int tun_buf_size = sizeof(thread->cpkt.iface_data);

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe))
		panic("Run out of SQE when reading from TUN fd (thread=%u)",
		      thread->idx);

	io_uring_prep_read(sqe, thread->tun_fd, tun_buf, tun_buf_size, 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TUN_READ));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		panic("io_uring_submit() when reading from TUN fd: " PRERF
		      " (thread=%u)", PREAR(-ret), thread->idx);

	return 0;
}


static int handle_tun_read(struct cli_thread *thread, struct io_uring_cqe *cqe)
{
	int ret;
	struct iou_cqe_vec *cqev;
	ssize_t read_ret = (ssize_t)cqe->res;
	struct tcli_pkt *cli_pkt, *cli_pkt0 = &thread->cpkt;

	if (unlikely(read_ret < 0)) {
		pr_err("read() from tun_fd " PRERF, PREAR((int)-read_ret));
		return (int)read_ret;
	}

	cqev = get_iou_cqe_vec(thread);
	if (unlikely(!cqev))
		return -EAGAIN;

	cli_pkt          = &cqev->cpkt;
	cli_pkt->type    = TCLI_PKT_IFACE_DATA;
	cli_pkt->pad_len = 0u;
	cli_pkt->length  = (uint16_t)((size_t)read_ret);
	cqev->vec_type   = IOU_CQE_VEC_TCP_SEND;
	cqev->len        = TCLI_PKT_MIN_READ + (size_t)read_ret;
	memcpy(&cli_pkt->iface_data, &cli_pkt0->iface_data, (size_t)read_ret);

	ret = do_iou_send(thread, thread->state->tcp_fd, cqev, 0);
	if (unlikely(ret < 0))
		return ret;

	pr_debug("TUN read %d bytes (thread=%u)", cqe->res, thread->idx);
	pr_debug("send() %zu bytes (thread=%u)", cqev->len, thread->idx);
	rearm_io_uring_read_tun(thread);
	return 0;
}


static int rearm_io_uring_recv(struct cli_thread *thread)
{
	int ret;
	int tcp_fd;
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	struct io_uring_sqe *sqe;
	struct cli_state *state = thread->state;

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe))
		panic("Running out of SQE when receiving data from the server");

	tcp_fd   = state->tcp_fd;
	recv_s   = state->recv_s;
	recv_buf = state->raw_pkt + recv_s;
	recv_len = sizeof(state->raw_pkt) - recv_s;

	io_uring_prep_recv(sqe, tcp_fd, recv_buf, recv_len, 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_VEC_TCP_RECV));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		panic("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		      thread->idx);

	return 0;
}


static int ____handle_server_data(struct cli_thread *thread, size_t recv_s)
{
	int ret = 0;
	struct cli_state *state = thread->state;
	struct tsrv_pkt *srv_pkt = &state->spkt;

	switch (srv_pkt->type) {
	case TSRV_PKT_NOP:
		break;
	case TSRV_PKT_HANDSHAKE:
		break;
	case TSRV_PKT_AUTH_RES:
		break;
	case TSRV_PKT_IFACE_DATA:
		pr_notice("Got TSRV_PKT_IFACE_DATA");
		break;
	case TSRV_PKT_REQSYNC:
		break;
	case TSRV_PKT_CLOSE:
		break;
	}
	return ret;
}


static int __handle_server_data(struct cli_thread *thread, size_t recv_s)
{
	int ret = 0;
	size_t fdata_len; /* Full expected data length for this packet    */
	size_t cdata_len; /* Current received data length for this packet */
	struct cli_state *state = thread->state;
	struct tsrv_pkt *srv_pkt = &state->spkt;

check_again:
	if (unlikely(recv_s < TSRV_PKT_MIN_READ)) {
		/*
		 * We haven't received mandatory information such
		 * as packet type, padding and data length.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}


	fdata_len = srv_pkt->length;
	cdata_len = recv_s - TSRV_PKT_MIN_READ;
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We haven't completely received the data.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}


	ret = ____handle_server_data(thread, fdata_len);
	if (unlikely(ret)) {
		recv_s = 0;
		goto out;
	}


	if (recv_s > (TCLI_PKT_MIN_READ + fdata_len)) {
		/*
		 * We have extra bytes on the tail.
		 *
		 * Must memmove() to the front before
		 * we run out of buffer!
		 */
		char *head  = (char *)srv_pkt;
		char *tail  = head + recv_s;
		recv_s     -= TSRV_PKT_MIN_READ + fdata_len;
		memmove(head, tail, recv_s);
		pr_debug("Got extra bytes, memmove() (recv_s = %zu)", recv_s);
		goto check_again;
	}


	/*
	 * We are done, reset the buffer offset to zero.
	 */
	recv_s = 0;
out:
	state->recv_s = recv_s;
	return ret;
}


static int handle_server_data(struct cli_thread *thread,
			      struct io_uring_cqe *cqe)
{
	int ret = 0;
	size_t recv_s;
	ssize_t recv_ret = (ssize_t)cqe->res;
	struct cli_state *state = thread->state;

	recv_s = state->recv_s;
	if (unlikely(recv_ret == 0)) {
		pr_notice("recv() from server returned 0");
		goto out_close;
	}

	if (unlikely(recv_ret < 0)) {
		pr_notice("recv() from server error | " PRERF,
			  PREAR((int)-recv_ret));
		goto out_close;
	}

	recv_s += (size_t)recv_ret;
	pr_debug("recv() %zd bytes from server (recv_s=%zu) (thread=%u)",
		 recv_ret, recv_s, thread->idx);

	ret = __handle_server_data(thread, recv_s);
	if (unlikely(ret && (ret != -EINPROGRESS))) {
		pr_debug("____handle_client_data returned " PRERF, PREAR(-ret));
		goto out_close;
	}

	rearm_io_uring_recv(thread);
	return 0;
out_close:
	return -ENETDOWN;
}


static int handle_iou_cqe_vec(struct cli_thread *thread,
			      struct io_uring_cqe *cqe, void *fret)
{
	int ret = 0;
	union uni_iou_cqe_vec *vcqe = fret;

	(void)cqe;
	switch (vcqe->vec_type) {
	case IOU_CQE_VEC_NOP:
		pr_notice("Got IOU_CQE_VEC_NOP");
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TUN_WRITE:
		pr_notice("Got IOU_CQE_VEC_TUN_WRITE");
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TCP_SEND:
		pr_notice("Got IOU_CQE_VEC_TCP_SEND");
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TCP_RECV:
		/* Don't put, it is not iou_cqe_vec! */
		break;
	default:
		VT_HEXDUMP(vcqe, 2048);
		panic("Got invalid vcqe on handle_iou_cqe_vec() (%u)",
		      vcqe->vec_type);
	}

	return ret;
}


static int handle_event(struct cli_thread *thread, struct io_uring_cqe *cqe)
{
	void *fret;
	int ret = 0;
	uintptr_t type;

	if (unlikely(!cqe))
		return 0;

	/*
	 * `fret` is just to shut the clang up!
	 */
	fret = io_uring_cqe_get_data(cqe);
	type = (uintptr_t)fret;
	switch (type) {
	case IOU_CQE_DRC_NOP:
		pr_notice("Got IOU_CQE_DRC_NOP");
		break;
	case IOU_CQE_DRC_TUN_READ:
		ret = handle_tun_read(thread, cqe);
		break;
	case IOU_CQE_DRC_TUN_RECV:
		ret = handle_server_data(thread, cqe);
		break;
	default:
		ret = handle_iou_cqe_vec(thread, cqe, fret);
		break;
	}

	return ret;

}


static int do_uring_wait(struct cli_thread *thread, struct io_uring_cqe **cqe_p)
{
	int ret;
	struct io_uring *ring = &thread->ring;
	struct __kernel_timespec *ts = &thread->ring_timeout;

	ret = io_uring_wait_cqes(ring, cqe_p, 1, ts, NULL);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME))
		return ret;

	if (unlikely(ret == -EINTR)) {
		pr_notice("Interrupted (thread=%u)", thread->idx);
		return -EINTR;
	}

	pr_err("io_uring_wait_cqe(): " PRERF, PREAR(-ret));
	return -ret;
}


static int handle_io_uring_cqes(struct cli_thread *thread,
				struct io_uring_cqe *cqe)
{
	int ret = 0;
	unsigned head, count = 0;
	struct io_uring *ring = &thread->ring;
	io_uring_for_each_cqe(ring, head, cqe) {
		count++;
		ret = handle_event(thread, cqe);
		if (unlikely(ret))
			break;
	}
	io_uring_cq_advance(ring, count);
	return ret;
}


static int do_io_uring_event_loop(struct cli_thread *thread)
{
	int ret;
	struct io_uring_cqe *cqe = NULL;

	ret = do_uring_wait(thread, &cqe);
	if (likely(ret == 0))
		return handle_io_uring_cqes(thread, cqe);
	

	if (unlikely(ret == -ETIME)) {
		/* io_uring reached its timeout. */
		return 0;
	}

	if (unlikely(ret == -EINTR)) {
		struct cli_state *state = thread->state;
		if (state->intr_sig == -1) {
			pr_notice("Ummm... are we traced? (thread=%u)",
				  thread->idx);
			return 0;
		}
		teavpn2_client_tcp_wait_for_thread_to_exit(state, true);
		return -EINTR;
	}
	return ret;
}


static void *run_thread(void *thread_p)
{
	int ret = 0;
	struct cli_thread *thread = thread_p;
	struct cli_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	teavpn2_client_tcp_wait_threads(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {
		ret = do_io_uring_event_loop(thread);
		if (unlikely(ret))
			break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	pr_notice("Thread %u is exiting (stop=%hhu)", thread->idx, state->stop);

	return (void *)(intptr_t)ret;

}


static int init_threads(struct cli_state *state)
{
	int ret = 0;
	struct cli_thread *threads;
	size_t i, nn = state->cfg->sys.thread;
	struct io_uring_params ring_params;
	const unsigned ring_flags = IORING_SETUP_CLAMP;

	threads = state->threads;

	for (i = 0; i < nn; i++) {
		struct io_uring_sqe *sqe;
		int tun_fd = state->tun_fds[i];
		struct cli_thread *thread = &threads[i];
		struct io_uring *ring = &thread->ring;
		void *tun_buf = &thread->cpkt.iface_data;
		unsigned int tun_buf_size = sizeof(thread->cpkt.iface_data);

		ret = tv_stack_init(&thread->ioucl_stk, IOUCL_VEC_NUM);
		if (unlikely(ret)) {
			pr_err("tv_stack_init(): " PRERF, PREAR(-ret));
			break;
		}

		ret = init_iou_cqe_vec(&thread->cqe_vec);
		if (unlikely(ret)) {
			pr_err("init_iou_cqe_vec(): " PRERF, PREAR(-ret));
			break;
		}

		memset(&ring_params, 0, sizeof(ring_params));
		ring_params.flags = ring_flags;

		ret = io_uring_queue_init_params(1u << 20u, ring, &ring_params);
		if (unlikely(ret)) {
			pr_err("io_uring_queue_init_params(): " PRERF,
			       PREAR(-ret));
			break;
		}

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


static int run_main_thread(struct cli_state *state)
{
	int ret;
	void *fret;
	struct io_uring_sqe *sqe;
	struct cli_thread *thread;
	int tcp_fd = state->tcp_fd;

	thread = &state->threads[0];
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe))
		panic("Cannot get SQE for initialization");

	io_uring_prep_recv(sqe, tcp_fd, &thread->cpkt, sizeof(thread->cpkt), 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TUN_RECV));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out;
	}

	fret = run_thread(thread);
	ret  = (int)((intptr_t)fret);
out:
	return ret;
}


static void destroy_io_uring_context(struct cli_state *state)
{
	struct cli_thread *threads = state->threads;
	size_t i, nn = state->cfg->sys.thread;

	for (i = 0; i < nn; i++) {
		struct cli_thread *thread = &threads[i];

		if (thread->ring_init)
			io_uring_queue_exit(&thread->ring);

		al64_free(thread->cqe_vec);
		tv_stack_destroy(&thread->ioucl_stk);
	}
}


int teavpn2_client_tcp_event_loop_io_uring(struct cli_state *state)
{
	int ret = 0;

	ret = init_threads(state);
	if (unlikely(ret)) {
		pr_err("init_threads(): " PRERF, PREAR(-ret));
		goto out;
	}

	ret = run_main_thread(state);
out:
	teavpn2_client_tcp_wait_for_thread_to_exit(state, false);
	destroy_io_uring_context(state);
	return ret;
}

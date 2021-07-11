// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TeaVPN2 server core for Linux.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "./tcp_common.h"

#define RING_BUFFER_COUNT ((size_t)(4096u * 2u))


static int init_ring_buffer(struct srv_thread *thread)
{
	struct srv_iou_rbuf *ring_buf;

	ring_buf = al64_malloc(RING_BUFFER_COUNT * sizeof(*ring_buf));
	if (unlikely(!ring_buf))
		return -ENOMEM;

	thread->ring_buf = ring_buf;
	return 0;
}


static int init_ring_buffer_stack(struct srv_thread *thread)
{
	int ret;
	uint16_t *arr;
	size_t nn = RING_BUFFER_COUNT;
	struct srv_stack *rb_stk = &thread->rb_stk;

	arr = calloc_wrp(nn, sizeof(*arr));
	if (unlikely(!arr)) {
		pr_err("al64_malloc(): " PRERF, PREAR(ENOMEM));
		return -ENOMEM;
	}

	ret = bt_mutex_init(&rb_stk->lock, NULL);
	if (unlikely(ret)) {
		pr_err("mutex_init(&rb_stk->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}

	rb_stk->sp = (uint16_t)nn;
	rb_stk->max_sp = (uint16_t)nn;
	rb_stk->arr = arr;

	while (nn--)
		srv_stk_push(rb_stk, (uint16_t)nn);

	BT_ASSERT(rb_stk->sp == 0);
	return 0;
}


static int do_uring_wait(struct srv_thread *thread, struct io_uring_cqe **cqe_p)
{
	int ret;
	struct __kernel_timespec *timeout = &thread->ring_timeout;

	ret = io_uring_wait_cqe_timeout(&thread->ring, cqe_p, timeout);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME))
		return ret;

	if (unlikely(ret == -EINTR)) {
		pr_notice("Interrupted (thread=%u)", thread->idx);
		return 0;
	}

	pr_err("io_uring_wait_cqe(): " PRERF, PREAR(-ret));
	return -ret;
}




static int __register_client(struct srv_thread *thread, int32_t idx, int cli_fd,
			     const char *src_ip, uint16_t src_port)
{
	int ret = 0;
	struct client_slot *client;
	struct io_uring_sqe *sqe = NULL;
	struct srv_thread *assignee = NULL;
	struct srv_state *state = thread->state;
	size_t i, num_threads = state->cfg->sys.thread;
	uint16_t th_idx = 0; /* Thread index (the assignee). */


	if (unlikely(num_threads <= 1)) {
		/*
		 * We are single threaded.
		 */
		assignee = thread;
		sqe = io_uring_get_sqe(&assignee->ring);
		goto out_reg;
	}


	for (i = 0; i < (num_threads + 1u); i++) {
		/*
		 * We are multi threaded.
		 */
		_Atomic(uint32_t) *tr_as = &state->tr_assign;


		th_idx   = atomic_fetch_add(tr_as, 1) % state->cfg->sys.thread;
		assignee = &state->threads[th_idx];


		/*
		 * Try to get sqe from the assigned thread.
		 *
		 * If it doesn't have free sqe, try again with
		 * different assignee.
		 */
		sqe = io_uring_get_sqe(&assignee->ring);
		if (unlikely(!sqe))
			/*
			 * Try again, check another thread!
			 */
			continue;


		/*
		 * We got a thread with free sqe. Go on!
		 */
		break;
	}



out_reg:
	if (unlikely(!sqe)) {
		/*
		 * We have checked all threads, but couldn't find
		 * free sqe. So we need to drop this client.
		 */
		return -EAGAIN;
	}

	ret = teavpn2_server_tcp_socket_setup(cli_fd, state);
	if (unlikely(ret < 0))
		goto out;

	client = &state->clients[idx];
	io_uring_prep_recv(sqe, cli_fd, client->raw_pkt,
			   sizeof(client->raw_pkt), MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);


	ret = io_uring_submit(&assignee->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out;
	}


	ret = 0;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;
	sane_strncpy(client->src_ip, src_ip, sizeof(client->src_ip));
	prl_notice(0, "New connection from " PRWIU " (fd=%d) (target_thread=%u)",
		   W_IU(client), cli_fd, th_idx);
out:
	return ret;
}


static int register_client(struct srv_thread *thread, int cli_fd)
{
	int ret = 0;
	int32_t idx;
	uint16_t src_port = 0;
	char src_ip[IPV4_L] = {0};
	struct srv_state *state = thread->state;

	/*
	 * The remote IP and port in big-endian representation.
	 */
	struct sockaddr_in *saddr = &state->acc.addr;
	struct in_addr *sin_addr = &saddr->sin_addr;

	/*
	 * Get the human readable IP address.
	 */
	if (unlikely(!inet_ntop(AF_INET, sin_addr, src_ip, sizeof(src_ip)))) {
		ret = errno;
		pr_err("inet_ntop(): " PRERF, PREAR(ret));
		ret = -ret;
		goto out_close;
	}
	src_ip[sizeof(src_ip) - 1] = '\0';
	src_port = ntohs(saddr->sin_port);


	/*
	 * Lookup for free client slot.
	 */
	bt_mutex_lock(&state->cl_stk.lock);
	idx = srv_stk_pop(&state->cl_stk);
	bt_mutex_unlock(&state->cl_stk.lock);
	if (unlikely(idx == -1)) {
		pr_err("Client slot is full, cannot accept connection from "
		       "%s:%u (thread=%u)", src_ip, src_port, thread->idx);
		ret = -EAGAIN;
		goto out_close;
	}


	/*
	 * Register the client to the client slot array.
	 */
	ret = __register_client(thread, idx, cli_fd, src_ip, src_port);
	if (unlikely(ret)) {
		/*
		 * We need to push back this index,
		 * because this popped `idx` is not
		 * used at the moment.
		 */
		goto out_close_push;
	}
	return 0;


out_close_push:
	bt_mutex_lock(&state->cl_stk.lock);
	srv_stk_push(&state->cl_stk, (uint16_t)idx);
	bt_mutex_unlock(&state->cl_stk.lock);


out_close:
	pr_notice("Closing connection from %s:%u (fd=%d) (thread=%u) Error: "
		  PRERF "...", src_ip, src_port, cli_fd, thread->idx,
		  PREAR(-ret));
	close(cli_fd);
	return ret;
}


static int handle_event_tcp(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0, cli_fd;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_state *state = thread->state;


	cli_fd = (int)cqe->res;
	io_uring_cqe_seen(&thread->ring, cqe);
	if (unlikely(cli_fd < 0)) {
		ret = cli_fd;
		goto out_err;
	}


	ret = register_client(thread, cli_fd);
	if (unlikely(ret))
		goto out_err;


out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Resource exhausted (thread=%u)", thread->idx);
		panic("io_uring run out of sqe on handle_event_tcp() "
		      "(thread=%u)", thread->idx);
		__builtin_unreachable();
	}

	acc          = &state->acc;
	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));

	io_uring_prep_accept(sqe, state->tcp_fd, (struct sockaddr *)&acc->addr,
			     &acc->addrlen, 0);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_CQE_TCP));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
	else
		ret = 0;

	return ret;

out_err:
	if (unlikely(ret == -EAGAIN))
		goto out_rearm;

	/*
	 * Fatal error, stop everything!
	 */
	pr_err("accpet(): " PRERF, PREAR(-ret));
	state->stop = true;
	return ret;
}


static int handle_event_tun(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0;
	int tun_fd = thread->tun_fd;
	struct io_uring_sqe *sqe;
	ssize_t read_ret = (ssize_t)cqe->res;

	io_uring_cqe_seen(&thread->ring, cqe);

	pr_debug("read() from tun_fd %zd bytes (fd=%d) (thread=%u)",
		 read_ret, tun_fd, thread->idx);

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Resource exhausted (thread=%u)", thread->idx);
		panic("io_uring run out of sqe on handle_event_tun() "
		      "(thread=%u)", thread->idx);
		__builtin_unreachable();
	}

	io_uring_prep_read(sqe, tun_fd, thread->spkt.raw_buf,
			   sizeof(thread->spkt.raw_buf), 0);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_CQE_TUN));

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		panic("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		      thread->idx);
		__builtin_unreachable();
	}
	ret = 0;

	return ret;
}


static struct srv_iou_rbuf *get_ring_buffer(struct srv_thread *thread)
{
	int32_t idx;
	struct srv_stack *rb_stk = &thread->rb_stk;
	struct srv_iou_rbuf *rbuf;

	bt_mutex_lock(&rb_stk->lock);
	idx = srv_stk_pop(rb_stk);
	bt_mutex_unlock(&rb_stk->lock);
	if (unlikely(idx == -1))
		return NULL;

	rbuf = &thread->ring_buf[idx];
	rbuf->ident = RING_QUE_CQEU_SEND;
	rbuf->idx = (uint16_t)idx;
	return rbuf;
}


static int handle_client_pkt_handshake(struct srv_thread *thread,
				       struct client_slot *client,
				       size_t fdata_len)
{
	int ret = 0;
	size_t send_len;
	struct tcli_pkt *cli_pkt = &client->cpkt;
	struct tsrv_pkt *srv_pkt;
	struct tcli_pkt_handshake *pkt_hsc = &cli_pkt->handshake;
	struct tsrv_pkt_handshake *pkt_hss;
	struct srv_iou_rbuf *rbuf;
	struct io_uring_sqe *sqe;

	/* For C string print safety. */
	pkt_hsc->cur.extra[sizeof(pkt_hsc->cur.extra) - 1] = '\0';

	pr_notice("Got protocol handshake from " PRWIU
		  " (TeaVPN2-v%hhu.%hhu.%hhu%s)",
		  W_IU(client),
		  pkt_hsc->cur.ver,
		  pkt_hsc->cur.patch_lvl,
		  pkt_hsc->cur.sub_lvl,
		  pkt_hsc->cur.extra);

	rbuf = get_ring_buffer(thread);
	if (unlikely(!rbuf))
		return -EAGAIN;

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		// put_ring_buffer(thread, rbuf);
		return -EAGAIN;
	}

	rbuf->client = client;
	srv_pkt = &rbuf->spkt;
	pkt_hss = &srv_pkt->handshake;
	pkt_hss->need_encryption = false;
	pkt_hss->has_min = false;
	pkt_hss->has_max = false;
	pkt_hss->cur.ver = VERSION;
	pkt_hss->cur.patch_lvl = PATCHLEVEL;
	pkt_hss->cur.sub_lvl = SUBLEVEL;
	sane_strncpy(pkt_hss->cur.extra, EXTRAVERSION,
		     sizeof(pkt_hss->cur.extra));

	srv_pkt->type = TSRV_PKT_HANDSHAKE;
	srv_pkt->pad_len = 0u;
	srv_pkt->length = sizeof(*pkt_hss);
	send_len = TCLI_PKT_MIN_READ + sizeof(*pkt_hss);
	rbuf->send_len = send_len;

	io_uring_prep_send(sqe, client->cli_fd, rbuf->raw_pkt, send_len, 0);
	io_uring_sqe_set_data(sqe, rbuf);

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		// put_ring_buffer(thread, rbuf);
		pr_err("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		       thread->idx);
	}

	ret = 0;
	return ret;
}


static int handle_client_pkt(struct srv_thread *thread,
			     struct client_slot *client, size_t fdata_len)
{
	int ret = 0;
	switch (client->cpkt.type) {
	case TCLI_PKT_NOP:
		break;
	case TCLI_PKT_HANDSHAKE:
		ret = handle_client_pkt_handshake(thread, client, fdata_len);
		break;
	case TCLI_PKT_IFACE_DATA:
		break;
	case TCLI_PKT_REQSYNC:
		break;
	case TCLI_PKT_CLOSE:
		break;
	}
	return ret;
}


static int __handle_event_client(struct srv_thread *thread,
				 struct client_slot *client, size_t recv_s)
{
	int ret = 0;
	size_t fdata_len; /* Full expected data length for this packet    */
	size_t cdata_len; /* Current received data length for this packet */
	struct io_uring_sqe *sqe;
	struct tcli_pkt *cli_pkt = &client->cpkt;


	client->recv_s = recv_s;
	if (unlikely(recv_s < TCLI_PKT_MIN_READ)) {
		/*
		 * We haven't received mandatory information such
		 * as packet type, padding and data length.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out_rearm;
	}


	fdata_len = cli_pkt->length;
	cdata_len = recv_s - TCLI_PKT_MIN_READ;
	if (unlikely(cdata_len < fdata_len)) {

		if (cdata_len >= (sizeof(*cli_pkt) - TCLI_PKT_MIN_READ)) {
			/* This is invalid packet. */
			recv_s = 0;
			client->recv_s = 0;
		}

		/*
		 * We haven't received the data completely.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out_rearm;
	}


	ret = handle_client_pkt(thread, client, fdata_len);
	if (unlikely(ret == -EAGAIN))
		ret = 0;
	else if (unlikely(ret))
		return ret;

	recv_s = 0;
	client->recv_s = 0;
	/* TODO: Handle extra tail */

out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Resource exhausted (thread=%u)", thread->idx);
		panic("io_uring run out of sqe on __handle_event_client() "
		      "(thread=%u)", thread->idx);
		__builtin_unreachable();
	}

	pr_notice("test = %zu", sizeof(client->raw_pkt) - recv_s);

	io_uring_prep_recv(sqe, client->cli_fd, client->raw_pkt + recv_s,
			   sizeof(client->raw_pkt) - recv_s, MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		pr_err("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		       thread->idx);
	return 0;
}


static void close_client_conn(struct srv_thread *thread,
			      struct client_slot *client)
{
	uint16_t cli_idx = client->idx;
	struct srv_state *state = thread->state;

	pr_notice("Closing connection from " PRWIU " (fd=%d) (thread=%u)...",
		  W_IU(client), client->cli_fd, thread->idx);

	close(client->cli_fd);
	reset_client_state(client, cli_idx);

	bt_mutex_lock(&state->cl_stk.lock);
	srv_stk_push(&state->cl_stk, cli_idx);
	bt_mutex_unlock(&state->cl_stk.lock);
}


static int handle_event_client(struct srv_thread *thread,
			       struct io_uring_cqe *cqe)
{
	int ret = 0;
	size_t recv_s;
	struct client_slot *client;
	ssize_t recv_ret = (ssize_t)cqe->res;


	client = io_uring_cqe_get_data(cqe);
	io_uring_cqe_seen(&thread->ring, cqe);
	recv_s = client->recv_s;

	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "recv() from " PRWIU " returned 0", W_IU(client));
		goto out_close;
	}

	if (unlikely(recv_ret < 0)) {
		prl_notice(0, "recv() from " PRWIU " error | " PRERF,
			   W_IU(client), PREAR((int)-recv_ret));
		goto out_close;
	}

	recv_s += (size_t)recv_ret;
	pr_debug("recv() %zd bytes from " PRWIU " (recv_s=%zu) (thread=%u)",
		 recv_s, W_IU(client), recv_ret, thread->idx);

	ret = __handle_event_client(thread, client, recv_s);
	if (unlikely(ret))
		goto out_close;

	return 0;

out_close:
	close_client_conn(thread, client);
	return ret;
}


static int handle_event_send_return(struct srv_thread *thread,
				    struct io_uring_cqe *cqe)
{
	int ret = 0;
	ssize_t send_ret;
	struct srv_iou_rbuf *rbuf;

	send_ret  = (ssize_t)cqe->res;
	rbuf      = io_uring_cqe_get_data(cqe);
	io_uring_cqe_seen(&thread->ring, cqe);

	pr_notice("send() %zd bytes to " PRWIU, send_ret, W_IU(rbuf->client));

	return ret;
}


static int handle_cqe_upointer(struct srv_thread *thread,
			       struct io_uring_cqe *cqe)
{
	int ret = 0;
	union ucqe_ring *ucqe = io_uring_cqe_get_data(cqe);

	switch (ucqe->ident) {
	case RING_QUE_CQEU_RECV:
		ret = handle_event_client(thread, cqe);
		break;
	case RING_QUE_CQEU_SEND:
		ret = handle_event_send_return(thread, cqe);
		break;
	default:
		panic("Invalid ident upointer");
	}

	return ret;
}


static int handle_event(struct srv_thread *thread, struct io_uring_cqe *cqe)
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
	case RING_QUE_CQE_NOP:
		io_uring_cqe_seen(&thread->ring, cqe);
		return 0;
	case RING_QUE_CQE_TCP:
		ret = handle_event_tcp(thread, cqe);
		break;
	case RING_QUE_CQE_TUN:
		ret = handle_event_tun(thread, cqe);
		break;
	default:
		ret = handle_cqe_upointer(thread, cqe);
		break;
	}

	return ret;
}


__no_inline static void *run_thread(void *thread_p)
{
	int ret = 0;
	struct io_uring_cqe *cqe;
	struct srv_thread *thread = thread_p;
	struct srv_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	teavpn2_server_tcp_wait_threads(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {
		cqe = NULL;
		ret = do_uring_wait(thread, &cqe);

		if (likely(ret == 0)) {
			ret = handle_event(thread, cqe);
			if (unlikely(ret))
				break;

			continue;
		}

		if (unlikely(ret == -ETIME))
			continue;

		break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	pr_notice("Thread %u is exiting (stop=%hhu)", thread->idx, state->stop);

	return (void *)(intptr_t)ret;
}


static int init_io_uring(struct srv_state *state)
{
	int ret = 0, *tun_fds = state->tun_fds;
	size_t i, nn = state->cfg->sys.thread;
	struct srv_thread *threads = state->threads;
	unsigned ring_flags = IORING_SETUP_CLAMP;

	/*
	 * Distribute tun_fds to all threads. So each thread has
	 * its own tun_fd for writing.
	 */
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		struct io_uring_sqe *sqe;
		struct srv_thread *thread;
		struct io_uring *ring;

		thread         = &threads[i];
		ring           = &thread->ring;
		thread->tun_fd = tun_fd;

		ret = io_uring_queue_init(1u << 24u, ring, ring_flags);
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
		io_uring_sqe_set_data(sqe, UPTR(RING_QUE_CQE_TUN));

		thread->ring_timeout.tv_sec = 10;


		ret = init_ring_buffer(thread);
		if (unlikely(ret))
			break;

		ret = init_ring_buffer_stack(thread);
		if (unlikely(ret))
			break;

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


static int run_main_thread(struct srv_state *state)
{
	int ret;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_thread *thread;

	/*
	 * Main thread is responsible to accept
	 * new connections, so we add tcp_fd to
	 * its uring queue resource.
	 */
	acc    = &state->acc;
	thread = &state->threads[0];

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
		ret = -ENOMEM;
		goto out;
	}

	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	io_uring_prep_accept(sqe, state->tcp_fd, (struct sockaddr *)&acc->addr,
			     &acc->addrlen, 0);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_CQE_TCP));

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


static void destroy_io_uring(struct srv_state *state)
{
	size_t i, nn = state->cfg->sys.thread;
	struct srv_thread *threads = state->threads, *thread;

	for (i = 0; i < nn; i++) {
		thread = &threads[i];
		if (thread->ring_init) {
			io_uring_queue_exit(&thread->ring);
		}
		bt_mutex_destroy(&thread->rb_stk.lock);
		al64_free(thread->rb_stk.arr);
		al64_free(thread->ring_buf);
	}
}


int teavpn2_server_tcp_event_loop_io_uring(struct srv_state *state)
{
	int ret;

	ret = init_io_uring(state);
	if (unlikely(ret))
		goto out;

	ret = run_main_thread(state);
out:
	teavpn2_server_tcp_wait_for_thread_to_exit(state);
	destroy_io_uring(state);
	return ret;
}

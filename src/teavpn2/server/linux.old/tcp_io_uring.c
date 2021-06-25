// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp_io_uring.c
 *
 *  TeaVPN2 server core for Linux (io_uring support).
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#include "tcp_common.h"


static int do_uring_wait(struct srv_thread *thread, struct io_uring_cqe **cqe_p)
{
	int ret;
	struct __kernel_timespec *timeout = &thread->ring_timeout;

	ret = io_uring_wait_cqe_timeout(&thread->ring, cqe_p, timeout);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME)) {
		timeout->tv_sec += 1;
		return ret;
	}

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
	size_t num_threads = state->cfg->sys.thread;
	uint16_t th_idx = 0; /* Thread index (the assignee). */


	if (unlikely(num_threads <= 1)) {
		/*
		 * We are single threaded.
		 */
		assignee = thread;
		sqe = io_uring_get_sqe(&assignee->ring);
		goto out_reg;
	}


	for (size_t i = 0; i < (num_threads + 1u); i++) {
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
	idx = srstk_pop(&state->cl_stk);
	bt_mutex_unlock(&state->cl_stk.lock);
	if (unlikely(idx == -1)) {
		pr_err("Client slot is full, cannot accept connection from "
		       "%s:%u", src_ip, src_port);
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
	srstk_push(&state->cl_stk, (uint16_t)idx);
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
	if (unlikely(!ret))
		goto out_rearm;


out_err:
	if (unlikely(ret == -EAGAIN))
		goto out_rearm;

	/*
	 * Fatal error, stop everything!
	 */
	pr_err("accpet(): " PRERF, PREAR(-ret));
	state->stop = true;
	return ret;


out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring run out of sqe on handle_event_tcp()");
		__builtin_unreachable();
	}


	acc          = &state->acc;
	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	io_uring_prep_accept(sqe, state->tcp_fd, (struct sockaddr *)&acc->addr,
			     &acc->addrlen, 0);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_TCP));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
	} else {
		ret = 0;
	}

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

	goto out_rearm;

out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring run out of sqe on handle_event_tcp()");
		__builtin_unreachable();
	}


	io_uring_prep_read(sqe, tun_fd, thread->spkt.raw_buf,
			   sizeof(thread->spkt.raw_buf), 0);
	io_uring_sqe_set_data(sqe, UPTR(RING_QUE_TUN));


	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		       thread->idx);
		return ret;
	}
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
	srstk_push(&state->cl_stk, cli_idx);
	bt_mutex_unlock(&state->cl_stk.lock);
}


static int __handle_event_client(struct srv_thread *thread,
				 struct client_slot *client)
{
	int ret = 0;
	struct io_uring_sqe *sqe;


	goto out_rearm;

out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring run out of sqe on handle_event_tcp()");
		__builtin_unreachable();
	}


	io_uring_prep_recv(sqe, client->cli_fd, client->raw_pkt,
			   sizeof(client->raw_pkt), MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);


	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		pr_err("io_uring_submit(): " PRERF " (thread=%u)", PREAR(-ret),
		       thread->idx);
	return 0;
}


static int handle_event_client(struct srv_thread *thread,
			       struct io_uring_cqe *cqe)
{
	int ret = 0;
	struct io_uring_sqe *sqe;
	struct client_slot *client;
	ssize_t recv_ret = (ssize_t)cqe->res;


	client = io_uring_cqe_get_data(cqe);
	io_uring_cqe_seen(&thread->ring, cqe);


	if (unlikely(recv_ret == 0)) {
		prl_notice(0, "recv() from " PRWIU " returned 0", W_IU(client));
		goto out_close;
	}


	if (unlikely(recv_ret < 0)) {
		prl_notice(0, "recv() from " PRWIU " error | " PRERF,
			   W_IU(client), PREAR((int)-recv_ret));
		goto out_close;
	}


	pr_debug("recv() %zd bytes from " PRWIU, recv_ret, W_IU(client));


	ret = __handle_event_client(thread, client);
	if (unlikely(ret))
		goto out_close;


	/* Just for clarity, nothing went wrong so far. */
	goto out_rearm;


out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Impossible happened!");
		panic("io_uring run out of sqe on handle_event_tcp()");
		__builtin_unreachable();
	}

	io_uring_prep_recv(sqe, client->cli_fd, client->raw_pkt,
			   sizeof(client->raw_pkt), MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);


	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out_close;
	}
	return 0;

out_close:
	close_client_conn(thread, client);
	return ret;
}


static int handle_event(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0;
	void *fret;
	uintptr_t type;

	/*
	 * `fret` is just to shut the clang up!
	 */
	fret = io_uring_cqe_get_data(cqe);
	type = (uintptr_t)fret;
	switch (type) {
	case RING_QUE_NOP:
		pr_err("Got RING_QUE_NOP on handle_event()");
		goto invalid_cqe;
	case RING_QUE_TCP:
		ret = handle_event_tcp(thread, cqe);
		break;
	case RING_QUE_TUN:
		ret = handle_event_tun(thread, cqe);
		break;
	default:
		ret = handle_event_client(thread, cqe);
		break;
	}

	return ret;


invalid_cqe:
	pr_emerg("Invalid CQE on handle_event() (thread=%u)", thread->idx);
	pr_emerg("Dumping CQE...");
	VT_HEXDUMP(cqe, sizeof(*cqe));
	panic("Invalid CQE!");
	__builtin_unreachable();
}


static __no_inline void *run_thread(void *_thread)
{
	intptr_t ret = 0;
	struct io_uring_cqe *cqe;
	struct srv_thread *thread = _thread;
	struct srv_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	wait_for_threads_to_be_ready(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {
		cqe = NULL;
		ret = do_uring_wait(thread, &cqe);
		if (unlikely(ret == -ETIME))
			continue;

		if (unlikely(ret))
			break;

		if (unlikely(!cqe))
			continue;

		ret = handle_event(thread, cqe);
		if (unlikely(ret))
			break;
	}

	if (thread->idx > 0)
		pr_notice("Thread %u is exiting...", thread->idx);

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	return (void *)ret;
}


static int spawn_threads(struct srv_state *state)
{
	size_t i;
	unsigned en_num; /* Number of queue entries */
	size_t nn = state->cfg->sys.thread;
	int ret = 0, *tun_fds = state->tun_fds;
	struct srv_thread *threads = state->threads;

	/*
	 * Distribute tun_fds to all threads. So each thread has
	 * its own tun_fds for writing.
	 */
	en_num = (state->cfg->sock.max_conn * 50u)
		+ (state->cfg->sys.thread * 50u)
		+ 30u;
	for (i = 0; i < nn; i++) {
		int tun_fd = tun_fds[i];
		struct io_uring_sqe *sqe;
		struct srv_thread *thread;
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


int teavpn2_server_tcp_run_io_uring(struct srv_state *state)
{
	int ret;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_thread *thread;


	ret = spawn_threads(state);
	if (unlikely(ret))
		goto out;


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

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


int teavpn2_server_tcp_run_io_uring(struct srv_state *state)
{
	return 0;
}

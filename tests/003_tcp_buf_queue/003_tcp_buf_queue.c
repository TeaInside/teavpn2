// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/003_tcp_buf_queue/003_tcp_buf_queue.c
 *
 *  Test case for TCP buffer queue.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <criterion/criterion.h>

#define TCP_BUF_QUEUE_TEST
#include <teavpn2/server/tcp_buf_queue.h>


Test(tcp_buf_queue, init_queue_must_be_empty)
{
	struct tcp_buf_queue queue;

	cr_assert_eq(tbq_init(&queue), &queue);
	cr_assert_eq(tbq_count(&queue), 0);
	cr_assert_eq(tbq_is_empty(&queue), true);

	tbq_destroy(&queue);
}

/*
 * TODO: Finish tcp_buf_queue
 */

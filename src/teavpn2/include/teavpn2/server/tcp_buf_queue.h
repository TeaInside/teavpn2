// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/server/tcp_buf_queue.h
 *
 *  TCP buffer queue.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__TCP_BUF_QUEUE_H
#define TEAVPN2__SERVER__TCP_BUF_QUEUE_H

#include <stdlib.h>
#include <teavpn2/base.h>


struct tcp_buf_queue {
	uint16_t		n;
};


#ifdef TCP_BUF_QUEUE_TEST
#  define inline_prod __no_inline
#else
#  define inline_prod inline
#endif


static inline_prod struct tcp_buf_queue *tbq_init(struct tcp_buf_queue *queue)
{
	queue->n = 0;
	return queue;
}


static inline_prod uint16_t tbq_count(struct tcp_buf_queue *queue)
{
	return queue->n;
}


static inline_prod bool tbq_is_empty(struct tcp_buf_queue *queue)
{
	return tbq_count(queue) == 0;
}


static inline_prod void tbq_destroy(struct tcp_buf_queue *queue)
{
	return;
}

#endif /* #ifndef TEAVPN2__SERVER__TCP_BUF_QUEUE_H */

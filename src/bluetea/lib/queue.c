// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/queue.c
 *
 *  Queue library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <bluetea/lib/queue.h>


bt_qnode_t *bt_qnode_create(size_t len)
{
	void *orig, *user, *shift_pos;
	uint8_t shift;

	orig = malloc(
		sizeof(bt_qnode_t) + len + 1ul	/* Node size        */
		+ 0x3full			/* Alignment backup */
		+ sizeof(uint8_t)		/* Origin track     */
	);

	if (unlikely(!orig))
		return NULL;

	user = (void *)(
		(
			(uintptr_t)orig
			+ 0x3full 		/* Alignment backup. */
			+ sizeof(uint8_t)	/* Origin track.     */
		)
		& ~0x3full /* Fix the alignment. */
	);

	shift     = (uint8_t)((uintptr_t)user - (uintptr_t)orig);
	shift_pos = (void *)((uintptr_t)user - 1);

	/*
	 * Store how many shift is done
	 * after fixing the alignment.
	 */
	memcpy(shift_pos, &shift, sizeof(uint8_t));
	return user;
}


static void bt_qnode_delete_ignore_ref(bt_qnode_t *user)
{
	void *orig, *shift_pos;
	uint8_t shift;

	shift_pos = (void *)((uintptr_t)user - 1);
	memcpy(&shift, shift_pos, sizeof(uint8_t));

	orig = (void *)((uintptr_t)user - (uintptr_t)shift);
	free(orig);
}


void bt_qnode_delete(bt_qnode_t *user)
{
	void *orig, *shift_pos;
	uint8_t shift;

	if (unlikely(!user))
		return;

	if (unlikely(user->next || user->prev)) {
		printf("FATAL: Trying to delete referenced node! Issuer: %s:%d\n",
		       __FILE__, __LINE__);
		abort();
	}

	shift_pos = (void *)((uintptr_t)user - 1);
	memcpy(&shift, shift_pos, sizeof(uint8_t));

	orig = (void *)((uintptr_t)user - (uintptr_t)shift);
	free(orig);
}


bt_qnode_t *bt_queue_enqueue(bt_queue_t *q, const void *data,
			     size_t len)
{
	bt_qnode_t *node;

	if (unlikely(q->count >= q->max_el)) {
		errno = EAGAIN;
		return NULL;
	}

	node = bt_qnode_create(len);
	if (unlikely(!node)) {
		errno = ENOMEM;
		return NULL;
	}

	node->next = NULL;
	node->prev = NULL;
	node->len  = len;
	memcpy(node->data, data, len);
	q->count++;

	if (unlikely(q->head == NULL)) {
		/*
		 * It's an empty queue.
		 */
		assert(q->tail == NULL);
		q->head = node;
		q->tail = node;
	} else {
		/* 
		 * Insert new queue to the tail.
		 */
		node->prev = q->tail;
		q->tail->next = node;
		q->tail = node;
	}

	return node;
}


bt_qnode_t *bt_queue_dequeue(bt_queue_t *q)
{
	bt_qnode_t *ret;

	if (unlikely(q->count == 0)) {
		errno = EAGAIN;
		return NULL;
	}

	assert(q->head);
	assert(q->head->prev == NULL);

	/*
	 * Consume queue from the head.
	 */
	ret     = q->head;
	q->head = q->head->next;

	if (q->head)
		q->head->prev = NULL;

	ret->prev = NULL;
	ret->next = NULL;
	q->count--;
	return ret;
}


__no_inline void *bt_qnode_data(bt_qnode_t *node)
{
	return node->data;
}


void bt_queue_destroy(bt_queue_t *q)
{
	uint32_t count;
	bt_qnode_t *head, *tmp;
	if (unlikely(q->count == 0))
		goto out;


	count = q->count;
	head  = q->head;
	while (head) {
		tmp  = head;
		head = head->next;
		bt_qnode_delete_ignore_ref(tmp);
		count--;
	}
	if (unlikely(count != 0)) {
		printf("FATAL: Invalid counter when iterating queue destroy! "
		       "Issuer: %s:%d\n", __FILE__, __LINE__);
		abort();
	}
out:
	memset(q, 0, sizeof(*q));
}


bt_qnode_t *bt_qnode_detach(bt_queue_t *q, bt_qnode_t *node)
{
	int err_ident = 1;

#ifndef NDEBUG
	/* 
	 * Strictly validate that the node is in the queue.
	 */
	bt_qnode_t *head, *tail;

	if (unlikely(q->count == 0))
		goto out_fatal;

	head = q->head;
	tail = q->tail;
	while (head || tail) {

		if (head == node || tail == node) {
			/*
			 * We found the node in the queue. Detach it!
			 */
			goto out_good;
		}

		if (head)
			head = head->next;
		if (tail)
			tail = tail->prev;
	}

	err_ident = 2;
	goto out_fatal;

out_good:
#endif
	if (node == q->head && node == q->tail) {
		if (unlikely(q->count != 1)) {
			err_ident = 3;
			goto out_fatal;
		}
		q->head = NULL;
		q->tail = NULL;
	} else if (node == q->head) {
		q->head = q->head->next;
		q->head->prev = NULL;
	} else if (node == q->tail) {
		q->tail = q->tail->prev;
		q->tail->next = NULL;
	} else {
		bt_qnode_t *next, *prev;
		next = node->next;
		prev = node->prev;
		next->prev = prev;
		prev->next = next;
	}

	node->next = NULL;
	node->prev = NULL;
	q->count--;
	return node;

out_fatal:
	printf("(%d) FATAL: Trying to detach invalid node! Issuer: %s:%d\n",
	       err_ident, __FILE__, __LINE__);
	abort();
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/teavpn2/lib/tstack.h
 *
 *  TStack
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__LIB__TSTACK_H
#define TEAVPN2__LIB__TSTACK_H

#include <errno.h>
#include <stdlib.h>
#include <stdalign.h>
#include <teavpn2/base.h>


#ifdef SQE_TEST
#  define inline_prod __no_inline
#else
#  define inline_prod inline
#endif

struct sqe_node;

struct sqe_node {
	struct sqe_node		*next;
	struct sqe_node 	*prev;
	size_t			len;
	alignas(16) char	data[];
};

struct sqe_master {
	struct sqe_node		*head;
	struct sqe_node		*tail;
	uint32_t		count;
	uint32_t		capacity;
};


static inline_prod struct sqe_master *sqe_init(struct sqe_master *sqe,
					       uint32_t capacity)
{
	sqe->head	= NULL;
	sqe->tail	= NULL;
	sqe->count	= 0;
	sqe->capacity	= capacity;
	return sqe;
}


static inline_prod uint32_t sqe_count(struct sqe_master *sqe)
{
	return sqe->count;
}


static inline_prod struct sqe_node *sqe_enqueue(struct sqe_master *sqe,
						const char *data,
						size_t len)
{
	struct sqe_node *node, *head, *tail;
	uint32_t capacity = sqe->capacity, count = sqe->count;

	if (unlikely(count >= capacity)) {
		errno = EAGAIN;
		return NULL;
	}

	node = malloc(sizeof(*node) + len + 1u);
	if (unlikely(node == NULL)) {
		int err = errno;
		pr_err("malloc(): " PRERF, PREAR(err));
		return NULL;
	}
	node->len = len;
	node->next = NULL;
	memcpy(node->data, data, len);


	head = sqe->head;
	tail = sqe->tail;

	if (unlikely(head == NULL)) {
		/*
		 * SQE is empty here
		 */

		/* Tail must be NULL if head is NULL */
		TASSERT(tail == NULL);

		head = node;
		tail = node;
		head->prev = NULL;


		sqe->head = head;
		sqe->tail = tail;
	} else {
		/*
		 * SQE is not empty
		 */
		TASSERT(head != NULL);
		TASSERT(tail != NULL);

		node->prev = tail;
		tail->next = node;
		tail = node;

		sqe->tail = tail;
	}

	sqe->count++;
	return node;
}


static inline_prod struct sqe_node *sqe_dequeue(struct sqe_master *sqe)
{
	struct sqe_node *ret, *head;
	struct sqe_node __maybe_unused *tail;

	if (unlikely(sqe->count == 0)) {
		/*
		 * SQE is empty
		 */

		TASSERT(sqe->head == NULL);
		TASSERT(sqe->tail == NULL);
		return NULL;
	}

	head = sqe->head;
	ret  = head;
	head = head->next;

	if (unlikely(head == NULL)) {
		tail = sqe->tail;

		/* SQE be empty after dequeue */
		TASSERT(sqe->count == 1);
		TASSERT(ret == tail);

		sqe->head = NULL;
		sqe->tail = NULL;
	} else {
		sqe->head = head;
	}

	sqe->count--;
	return ret;
}


static inline_prod void sqe_node_destroy(struct sqe_node *node)
{
	free(node);
}


static inline_prod void sqe_destroy(struct sqe_master *sqe)
{
	struct sqe_node *head, *tmp;

	if (unlikely(sqe->count == 0))
		goto out;

	head = sqe->head;
	while (head) {
		tmp  = head;
		head = head->next;
		sqe_node_destroy(tmp);
	}
out:
	sqe_init(sqe, 0);
}


#endif

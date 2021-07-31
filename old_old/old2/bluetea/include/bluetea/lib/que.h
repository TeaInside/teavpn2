// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/lib/que.h
 *
 *  Queue library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__LIB__QUE_H
#define BLUETEA__LIB__QUE_H

#include <errno.h>
#include <stdlib.h>
#include <stdalign.h>
#include <bluetea/base.h>


#ifdef QUE_TEST
#  define inline_prod __no_inline
#else
#  define inline_prod inline
#endif

struct que_node;

struct que_node {
	struct que_node		*next;
	struct que_node 	*prev;
	size_t			len;
	alignas(64) char	data[];
};

struct que_master {
	struct que_node		*head;
	struct que_node		*tail;
	uint32_t		count;
	uint32_t		capacity;
};


static inline_prod struct que_master *que_init(struct que_master *que,
					       uint32_t capacity)
{
	que->head	= NULL;
	que->tail	= NULL;
	que->count	= 0;
	que->capacity	= capacity;
	return que;
}


static inline_prod uint32_t que_count(struct que_master *que)
{
	return que->count;
}


static inline_prod struct que_node *que_enqueue(struct que_master *que,
						const char *data,
						size_t len)
{
	struct que_node *node, *head, *tail;
	uint32_t capacity = que->capacity, count = que->count;

	if (unlikely(count >= capacity)) {
		errno = EAGAIN;
		return NULL;
	}

	node = aligned_alloc(64u, sizeof(*node) + len + 2u);
	if (unlikely(node == NULL)) {
		int err = errno;
		pr_err("malloc(): " PRERF, PREAR(err));
		return NULL;
	}
	node->len = len;
	node->next = NULL;
	memcpy(node->data, data, len);
	node->data[len] = '\0';


	head = que->head;
	tail = que->tail;

	if (unlikely(head == NULL)) {
		/*
		 * QUE is empty here
		 */

		/* Tail must be NULL if head is NULL */
		TASSERT(tail == NULL);

		head = node;
		tail = node;
		head->prev = NULL;


		que->head = head;
		que->tail = tail;
	} else {
		/*
		 * QUE is not empty
		 */
		TASSERT(head != NULL);
		TASSERT(tail != NULL);

		node->prev = tail;
		tail->next = node;
		tail = node;

		que->tail = tail;
	}

	que->count++;
	return node;
}


static inline_prod struct que_node *que_dequeue(struct que_master *que)
{
	struct que_node *ret, *head;
	struct que_node __maybe_unused *tail;

	if (unlikely(que->count == 0)) {
		/*
		 * QUE is empty
		 */

		TASSERT(que->head == NULL);
		TASSERT(que->tail == NULL);
		return NULL;
	}

	head = que->head;
	ret  = head;
	head = head->next;

	if (unlikely(head == NULL)) {
		tail = que->tail;

		/* QUE be empty after dequeue */
		TASSERT(que->count == 1);
		TASSERT(ret == tail);

		que->head = NULL;
		que->tail = NULL;
	} else {
		que->head = head;
	}

	que->count--;
	return ret;
}


static inline_prod void que_node_destroy(struct que_node *node)
{
	free(node);
}


static inline_prod void que_destroy(struct que_master *que)
{
	struct que_node *head, *tmp;

	if (unlikely(que->count == 0))
		goto out;

	head = que->head;
	while (head) {
		tmp  = head;
		head = head->next;
		que_node_destroy(tmp);
	}
out:
	que_init(que, 0);
}


#endif /* #ifndef BLUETEA__LIB__QUE_H */

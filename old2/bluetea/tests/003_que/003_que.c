// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/tests/003_que/003_que.c
 *
 *  Test case for queue
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/teatest.h>
#include <bluetea/base.h>
#include <bluetea/lib/string.h>

#define QUE_TEST (1)
#include <bluetea/lib/que.h>


static TEATEST(003_que, init_que_must_be_empty)
{
	TQ_START;
	struct que_master que;

	TQ_ASSERT(que_init(&que, 100) == &que);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_VOID(que_destroy(&que));
	TQ_RETURN;
}


static TEATEST(003_que, que_enqueue_must_increment_count)
{
	TQ_START;
	struct que_master que;

	TQ_ASSERT(que_init(&que, 5) == &que);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_enqueue(&que, "AAA", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 1);
	TQ_ASSERT(que_enqueue(&que, "BBB", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 2);
	TQ_ASSERT(que_enqueue(&que, "CCC", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 3);
	TQ_ASSERT(que_enqueue(&que, "DDD", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 4);
	TQ_ASSERT(que_enqueue(&que, "EEE", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 5);

	/* Dequeue on full QUE returns NULL and set errno to EAGAIN */
	TQ_ASSERT((que_enqueue(&que, "FFF", 4) == NULL) && (errno == EAGAIN));
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT((que_enqueue(&que, "GGG", 4) == NULL)  && (errno == EAGAIN));
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT((que_enqueue(&que, "HHH", 4) == NULL)  && (errno == EAGAIN));
	TQ_ASSERT(que_count(&que) == 5);

	TQ_VOID(que_destroy(&que));
	TQ_RETURN;
}


static TEATEST(003_que, que_dequeue_must_decrement_count_and_must_be_fifo)
{
	TQ_START;
	struct que_master que;
	struct que_node *node = NULL;

	TQ_ASSERT(que_init(&que, 100) == &que);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_enqueue(&que, "AAA", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "BBB", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "CCC", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "DDD", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "EEE", 4) != NULL);

	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("AAA", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 4);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("BBB", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 3);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("CCC", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 2);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("DDD", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 1);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("EEE", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 0);


	/* Dequeue on empty QUE yields NULL */
	TQ_ASSERT(que_dequeue(&que) == NULL);
	TQ_ASSERT(que_count(&que) == 0);
	TQ_ASSERT(que_dequeue(&que) == NULL);
	TQ_ASSERT(que_count(&que) == 0);


	TQ_VOID(que_destroy(&que));
	TQ_RETURN;
}


static TEATEST(003_que, que_must_maintain_the_fifo)
{
	TQ_START;
	struct que_master que;
	struct que_node *node = NULL;

	TQ_ASSERT(que_init(&que, 10) == &que);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_enqueue(&que, "AAA", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "BBB", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "CCC", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "DDD", 4) != NULL);
	TQ_ASSERT(que_enqueue(&que, "EEE", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("AAA", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 4);

	TQ_ASSERT(que_enqueue(&que, "FFF", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("BBB", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 4);

	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("CCC", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 4);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("DDD", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 3);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("EEE", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 2);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("FFF", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 1);

	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 2);
	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 3);
	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 4);
	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 5);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 4);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 3);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 2);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 1);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_dequeue(&que) == NULL);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_dequeue(&que) == NULL);
	TQ_ASSERT(que_count(&que) == 0);

	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 1);

	TQ_ASSERT(que_enqueue(&que, "GGG", 4) != NULL);
	TQ_ASSERT(que_count(&que) == 2);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 1);

	TQ_ASSERT(node = que_dequeue(&que));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(que_node_destroy(node));
	TQ_ASSERT(que_count(&que) == 0);

	TQ_VOID(que_destroy(&que));
	TQ_RETURN;
}


extern const test_entry_t test_entry_arr[];
const test_entry_t test_entry_arr[] = {
	FN_TEATEST(003_que, init_que_must_be_empty),
	FN_TEATEST(003_que, que_enqueue_must_increment_count),
	FN_TEATEST(003_que, que_dequeue_must_decrement_count_and_must_be_fifo),
	FN_TEATEST(003_que, que_must_maintain_the_fifo),
	NULL
};

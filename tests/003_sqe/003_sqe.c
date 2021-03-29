// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/001_string/001_string.c
 *
 *  Test case for SQE
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teatest.h>
#include <teavpn2/base.h>

#define SQE_TEST (1)
#include <teavpn2/lib/sqe.h>


static TEATEST(003_sqe, init_sqe_must_be_empty)
{
	TQ_START;
	struct sqe_master sqe;

	TQ_ASSERT(sqe_init(&sqe, 100) == &sqe);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_VOID(sqe_destroy(&sqe));
	TQ_RETURN;
}


static TEATEST(003_sqe, sqe_enqueue_must_increment_count)
{
	TQ_START;
	struct sqe_master sqe;

	TQ_ASSERT(sqe_init(&sqe, 5) == &sqe);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_enqueue(&sqe, "AAA", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 1);
	TQ_ASSERT(sqe_enqueue(&sqe, "BBB", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 2);
	TQ_ASSERT(sqe_enqueue(&sqe, "CCC", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 3);
	TQ_ASSERT(sqe_enqueue(&sqe, "DDD", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 4);
	TQ_ASSERT(sqe_enqueue(&sqe, "EEE", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 5);

	/* Dequeue on full SQE returns NULL and set errno to EAGAIN */
	TQ_ASSERT((sqe_enqueue(&sqe, "FFF", 4) == NULL) && (errno == EAGAIN));
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT((sqe_enqueue(&sqe, "GGG", 4) == NULL)  && (errno == EAGAIN));
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT((sqe_enqueue(&sqe, "HHH", 4) == NULL)  && (errno == EAGAIN));
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_VOID(sqe_destroy(&sqe));
	TQ_RETURN;
}


static TEATEST(003_sqe, sqe_dequeue_must_decrement_count_and_must_be_fifo)
{
	TQ_START;
	struct sqe_master sqe;
	struct sqe_node *node;

	TQ_ASSERT(sqe_init(&sqe, 100) == &sqe);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_enqueue(&sqe, "AAA", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "BBB", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "CCC", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "DDD", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "EEE", 4) != NULL);

	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("AAA", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 4);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("BBB", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 3);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("CCC", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 2);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("DDD", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 1);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("EEE", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 0);


	/* Dequeue on empty SQE yields NULL */
	TQ_ASSERT(sqe_dequeue(&sqe) == NULL);
	TQ_ASSERT(sqe_count(&sqe) == 0);
	TQ_ASSERT(sqe_dequeue(&sqe) == NULL);
	TQ_ASSERT(sqe_count(&sqe) == 0);


	TQ_VOID(sqe_destroy(&sqe));
	TQ_RETURN;
}


static TEATEST(003_sqe, sqe_must_maintain_the_fifo)
{
	TQ_START;
	struct sqe_master sqe;
	struct sqe_node *node;

	TQ_ASSERT(sqe_init(&sqe, 10) == &sqe);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_enqueue(&sqe, "AAA", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "BBB", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "CCC", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "DDD", 4) != NULL);
	TQ_ASSERT(sqe_enqueue(&sqe, "EEE", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("AAA", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 4);

	TQ_ASSERT(sqe_enqueue(&sqe, "FFF", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("BBB", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 4);

	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("CCC", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 4);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("DDD", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 3);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("EEE", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 2);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("FFF", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 1);

	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 2);
	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 3);
	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 4);
	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 5);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 4);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 3);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 2);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 1);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_dequeue(&sqe) == NULL);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_dequeue(&sqe) == NULL);
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 1);

	TQ_ASSERT(sqe_enqueue(&sqe, "GGG", 4) != NULL);
	TQ_ASSERT(sqe_count(&sqe) == 2);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 1);

	TQ_ASSERT(node = sqe_dequeue(&sqe));
	TQ_ASSERT(node->len == 4);
	TQ_ASSERT(!strcmp("GGG", node->data));
	TQ_VOID(sqe_node_destroy(node));
	TQ_ASSERT(sqe_count(&sqe) == 0);

	TQ_VOID(sqe_destroy(&sqe));
	TQ_RETURN;
}


static const test_entry_t entry[] = {
	FN_TEATEST(003_sqe, init_sqe_must_be_empty),
	FN_TEATEST(003_sqe, sqe_enqueue_must_increment_count),
	FN_TEATEST(003_sqe, sqe_dequeue_must_decrement_count_and_must_be_fifo),
	FN_TEATEST(003_sqe, sqe_must_maintain_the_fifo),
	NULL
};


int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return spawn_valgrind(argc, argv);


	ret = init_test(entry);
	if (ret != 0)
		return ret;

	ret = run_test(entry);
	return ret;
}

// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/tests/002_tstack/002_tstack.c
 *
 *  Test case for stack
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/teatest.h>
#include <bluetea/base.h>
#include <bluetea/lib/string.h>

#define TSTACK_TEST (1)
#include <bluetea/lib/tstack.h>


static TEATEST(002_tstack, init_stack_must_be_empty)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 100) == &st);
	TQ_ASSERT(tss_count(&st) == 0);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}


static TEATEST(002_tstack, push_must_increment_the_count)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 100) == &st);
	TQ_ASSERT(tss_count(&st) == 0);

	TQ_ASSERT(tss_push(&st, 1) == 1);
	TQ_ASSERT(tss_count(&st) == 1);

	TQ_ASSERT(tss_push(&st, 2) == 2);
	TQ_ASSERT(tss_count(&st) == 2);

	TQ_ASSERT(tss_push(&st, 3) == 3);
	TQ_ASSERT(tss_count(&st) == 3);

	TQ_ASSERT(tss_push(&st, 4) == 4);
	TQ_ASSERT(tss_count(&st) == 4);

	TQ_ASSERT(tss_push(&st, 5) == 5);
	TQ_ASSERT(tss_count(&st) == 5);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}


static TEATEST(002_tstack, pop_must_decrement_the_count_and_must_be_lifo)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 100) == &st);
	TQ_ASSERT(tss_push(&st, 1) == 1);
	TQ_ASSERT(tss_push(&st, 2) == 2);
	TQ_ASSERT(tss_push(&st, 3) == 3);
	TQ_ASSERT(tss_push(&st, 4) == 4);
	TQ_ASSERT(tss_push(&st, 5) == 5);

	TQ_ASSERT(tss_count(&st) == 5);
	TQ_ASSERT(tss_pop(&st) == 5);
	TQ_ASSERT(tss_count(&st) == 4);
	TQ_ASSERT(tss_pop(&st) == 4);
	TQ_ASSERT(tss_count(&st) == 3);
	TQ_ASSERT(tss_pop(&st) == 3);
	TQ_ASSERT(tss_count(&st) == 2);
	TQ_ASSERT(tss_pop(&st) == 2);
	TQ_ASSERT(tss_count(&st) == 1);
	TQ_ASSERT(tss_pop(&st) == 1);
	TQ_ASSERT(tss_count(&st) == 0);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}


static TEATEST(002_tstack, push_after_full_returns_neg_one)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 4) == &st);
	TQ_ASSERT(tss_push(&st, 1) == 1);
	TQ_ASSERT(tss_push(&st, 2) == 2);
	TQ_ASSERT(tss_push(&st, 3) == 3);
	TQ_ASSERT(tss_push(&st, 4) == 4);
	TQ_ASSERT(tss_push(&st, 5) == -1);
	TQ_ASSERT(tss_push(&st, 6) == -1);
	TQ_ASSERT(tss_push(&st, 7) == -1);
	TQ_ASSERT(tss_push(&st, 8) == -1);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}


static TEATEST(002_tstack, pop_on_empty_stack_returns_neg_one)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 4) == &st);
	TQ_ASSERT(tss_pop(&st) == -1);
	TQ_ASSERT(tss_push(&st, 1) == 1);
	TQ_ASSERT(tss_pop(&st) == 1);

	TQ_ASSERT(tss_push(&st, 2) == 2);
	TQ_ASSERT(tss_pop(&st) == 2);

	TQ_ASSERT(tss_push(&st, 3) == 3);
	TQ_ASSERT(tss_pop(&st) == 3);

	TQ_ASSERT(tss_push(&st, 4) == 4);
	TQ_ASSERT(tss_pop(&st) == 4);

	TQ_ASSERT(tss_pop(&st) == -1);
	TQ_ASSERT(tss_pop(&st) == -1);
	TQ_ASSERT(tss_pop(&st) == -1);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}


static TEATEST(002_tstack, push_and_pop_maintain_the_lifo_properly)
{
	TQ_START;
	struct tstack st;

	TQ_ASSERT(tss_init(&st, 10) == &st);
	TQ_ASSERT(tss_pop(&st) == -1);
	TQ_ASSERT(tss_pop(&st) == -1);

	TQ_ASSERT(tss_push(&st, 10) == 10);
	TQ_ASSERT(tss_push(&st, 9) == 9);
	TQ_ASSERT(tss_push(&st, 8) == 8);
	TQ_ASSERT(tss_pop(&st) == 8);
	TQ_ASSERT(tss_push(&st, 99) == 99);
	TQ_ASSERT(tss_pop(&st) == 99);
	TQ_ASSERT(tss_pop(&st) == 9);
	TQ_ASSERT(tss_pop(&st) == 10);
	TQ_ASSERT(tss_pop(&st) == -1);

	TQ_VOID(tss_destroy(&st));
	TQ_RETURN;
}



extern const test_entry_t test_entry_arr[];
const test_entry_t test_entry_arr[] = {
	FN_TEATEST(002_tstack, init_stack_must_be_empty),
	FN_TEATEST(002_tstack, push_must_increment_the_count),
	FN_TEATEST(002_tstack, pop_must_decrement_the_count_and_must_be_lifo),
	FN_TEATEST(002_tstack, push_after_full_returns_neg_one),
	FN_TEATEST(002_tstack, pop_on_empty_stack_returns_neg_one),
	FN_TEATEST(002_tstack, push_and_pop_maintain_the_lifo_properly),
	NULL
};

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/001_string/001_string.c
 *
 *  Test case for stack
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teatest.h>
#include <teavpn2/base.h>

#define TSTACK_TEST (1)
#include <teavpn2/lib/tstack.h>


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


static const test_entry_t entry[] = {
	FN_TEATEST(002_tstack, init_stack_must_be_empty),
	FN_TEATEST(002_tstack, push_must_increment_the_count),
	FN_TEATEST(002_tstack, pop_must_decrement_the_count_and_must_be_lifo),
	FN_TEATEST(002_tstack, push_after_full_returns_neg_one),
	FN_TEATEST(002_tstack, pop_on_empty_stack_returns_neg_one),
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

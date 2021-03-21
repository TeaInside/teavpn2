// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/004_tcp_slot_stack/004_tcp_slot_stack.c
 *
 *  Test case for TCP buffer queue.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <criterion/criterion.h>

#define TCP_SLOT_STACK_TEST
#include <teavpn2/server/tcp_slot_stack.h>


Test(tcp_slot_stack, init_stack_must_be_empty)
{
	struct tcp_slot_stack stack;

	cr_assert_eq(tss_init(&stack, 100), &stack);
	cr_assert_eq(tss_count(&stack), 0);
	cr_assert_eq(tss_capacity(&stack), 100);
	cr_assert_eq(tss_is_empty(&stack), true);

	tss_destroy(&stack);
}


Test(tcp_slot_stack, after_push_stack_must_not_be_empty_and_the_count_maintain)
{
	struct tcp_slot_stack stack;

	cr_assert_eq(tss_init(&stack, 100), &stack);
	cr_assert_eq(tss_capacity(&stack), 100);

	cr_assert_eq(tss_push(&stack, 10), 10);
	cr_assert_eq(tss_count(&stack), 1);
	cr_assert_eq(tss_is_empty(&stack), false);

	cr_assert_eq(tss_push(&stack, 20), 20);
	cr_assert_eq(tss_count(&stack), 2);
	cr_assert_eq(tss_is_empty(&stack), false);

	cr_assert_eq(tss_push(&stack, 30), 30);
	cr_assert_eq(tss_count(&stack), 3);
	cr_assert_eq(tss_is_empty(&stack), false);

	tss_destroy(&stack);
}


Test(tcp_slot_stack, push_more_than_capacity_must_return_neg_one)
{
	struct tcp_slot_stack stack;

	cr_assert_eq(tss_init(&stack, 3), &stack);
	cr_assert_eq(tss_capacity(&stack), 3);

	cr_assert_eq(tss_push(&stack, 10), 10);
	cr_assert_eq(tss_push(&stack, 20), 20);
	cr_assert_eq(tss_push(&stack, 30), 30);
	cr_assert_eq(tss_push(&stack, 40), -1);
	cr_assert_eq(tss_push(&stack, 50), -1);
	cr_assert_eq(tss_push(&stack, 60), -1);

	tss_destroy(&stack);
}


Test(tcp_slot_stack, stack_must_behave_as_lifo1)
{
	struct tcp_slot_stack stack;

	cr_assert_eq(tss_init(&stack, 10), &stack);
	cr_assert_eq(tss_capacity(&stack), 10);

	cr_assert_eq(tss_push(&stack, 10), 10);
	cr_assert_eq(tss_pop(&stack), 10);

	cr_assert_eq(tss_push(&stack, 10), 10);
	cr_assert_eq(tss_push(&stack, 20), 20);
	cr_assert_eq(tss_pop(&stack), 20);
	cr_assert_eq(tss_pop(&stack), 10);

	cr_assert_eq(tss_push(&stack, 10), 10);
	cr_assert_eq(tss_push(&stack, 20), 20);
	cr_assert_eq(tss_push(&stack, 30), 30);
	cr_assert_eq(tss_push(&stack, 40), 40);
	cr_assert_eq(tss_push(&stack, 50), 50);
	cr_assert_eq(tss_push(&stack, 60), 60);
	cr_assert_eq(tss_push(&stack, 70), 70);
	cr_assert_eq(tss_push(&stack, 80), 80);
	cr_assert_eq(tss_push(&stack, 90), 90);
	cr_assert_eq(tss_push(&stack, 100), 100);

	/* Stack overflow */
	cr_assert_eq(tss_push(&stack, 110), -1);

	cr_assert_eq(tss_pop(&stack), 100);
	cr_assert_eq(tss_pop(&stack), 90);
	cr_assert_eq(tss_pop(&stack), 80);
	cr_assert_eq(tss_pop(&stack), 70);
	cr_assert_eq(tss_pop(&stack), 60);
	cr_assert_eq(tss_pop(&stack), 50);
	cr_assert_eq(tss_pop(&stack), 40);
	cr_assert_eq(tss_pop(&stack), 30);
	cr_assert_eq(tss_pop(&stack), 20);
	cr_assert_eq(tss_pop(&stack), 10);

	/* Stack undeflow */
	cr_assert_eq(tss_pop(&stack), -1);

	tss_destroy(&stack);
}


Test(tcp_slot_stack, stack_must_behave_as_lifo2)
{
	uint16_t i;
	struct tcp_slot_stack stack;

	cr_assert_eq(tss_init(&stack, 1000), &stack);
	cr_assert_eq(tss_capacity(&stack), 1000);

	for (i = 0; i < 1000; i++) {
		cr_assert_eq(tss_push(&stack, i), (int32_t)i);
	}

	while (i-- >= 500)
		cr_assert_eq(tss_pop(&stack), (int32_t)i);

	while (i++ <= 3000) {
		int32_t cmp = (i >= 1000) ? -1 : (int32_t)i;
		cr_assert_eq(tss_push(&stack, i), cmp);
	}

	i = 1000;
	while (i--) {
		cr_assert_eq(tss_pop(&stack), (int32_t)i);
	}

	tss_destroy(&stack);
}

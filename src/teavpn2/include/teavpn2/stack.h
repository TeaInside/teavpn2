// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/stack.h
 *
 *  Printing header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__STACK_H
#define TEAVPN2__STACK_H

#include <teavpn2/allocator.h>
#include <bluetea/lib/mutex.h>

struct tv_stack {
	struct bt_mutex				lock;
	uint16_t				*arr;
	uint16_t				sp;
	uint16_t				max_sp;
};


static inline int32_t tv_stack_push(struct tv_stack *stack, uint16_t idx)
{
	uint16_t sp = stack->sp;

	if (unlikely(sp == 0))
		/*
		 * Stack is full.
		 */
		return -1;

	stack->arr[--sp] = idx;
	stack->sp = sp;
	return (int32_t)idx;
}


static inline int32_t tv_stack_pop(struct tv_stack *stack)
{
	int32_t ret;
	uint16_t sp = stack->sp;
	uint16_t max_sp = stack->max_sp;

	assert(sp <= max_sp);
	if (unlikely(sp == max_sp))
		/*
		 * Stack is empty.
		 */
		return -1;

	ret = (int32_t)stack->arr[sp++];
	stack->sp = sp;
	return ret;
}


static inline void __assert_tv_stack(struct tv_stack *stack, uint16_t capacity)
{
#ifndef NDEBUG
	int ret;
	size_t i;

	/*
	 * Push stack.
	 */
	for (i = 0; i < capacity; i++) {
		ret = tv_stack_push(stack, (uint16_t)i);
		__asm__ volatile("":"+m"(stack)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}

	/*
	 * Push full stack.
	 */
	for (i = 0; i < 100; i++) {
		ret = tv_stack_push(stack, (uint16_t)i);
		__asm__ volatile("":"+m"(stack)::"memory");
		BT_ASSERT(ret == -1);
	}

	/*
	 * Pop stack.
	 */
	for (i = capacity; i--;) {
		ret = tv_stack_pop(stack);
		__asm__ volatile("":"+m"(stack)::"memory");
		BT_ASSERT((uint16_t)ret == (uint16_t)i);
	}


	/*
	 * Pop empty stack.
	 */
	for (i = 0; i < 100; i++) {
		ret = tv_stack_pop(stack);
		__asm__ volatile("":"+m"(stack)::"memory");
		BT_ASSERT(ret == -1);
	}
#else
	(void)stack;
	(void)capacity;
#endif
}


static inline int tv_stack_init(struct tv_stack *stack, uint16_t capacity)
{
	int ret;
	uint16_t *arr;

	arr = al64_calloc_wrp(capacity, sizeof(*arr));
	if (unlikely(!arr))
		return -ENOMEM;

	ret = bt_mutex_init(&stack->lock, NULL);
	if (unlikely(ret)) {
		al64_free(arr);
		pr_err("mutex_init(&stack->lock, NULL): " PRERF, PREAR(ret));
		return -ret;
	}

	stack->sp = capacity;
	stack->max_sp = capacity;
	stack->arr = arr;

	__assert_tv_stack(stack, capacity);

	while (capacity--)
		tv_stack_push(stack, (uint16_t)capacity);

	BT_ASSERT(stack->sp == 0);
	return 0;
}


static inline void tv_stack_destroy(struct tv_stack *stack)
{
	al64_free(stack->arr);
	bt_mutex_destroy(&stack->lock);
}

#endif /* #ifndef TEAVPN2__STACK_H */

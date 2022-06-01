// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__STACK_H
#define TEAVPN2__STACK_H

#include <stdint.h>
#include <teavpn2/common.h>


struct bt_stack {
	uint16_t		sp;
	uint16_t		max_sp;
	uint16_t		*arr;
};


static inline int32_t bt_stack_pop(struct bt_stack *stk)
{
	int32_t ret;
	uint16_t sp = stk->sp;

	if (sp == stk->max_sp)
		/* Stack is empty. */
		return -1;

	ret = (int32_t)stk->arr[sp++];
	stk->sp = sp;
	return ret;
}


static inline int32_t bt_stack_push(struct bt_stack *stk, uint16_t n)
{
	uint16_t sp = stk->sp;

	if (sp == 0)
		/* Stack is full. */
		return -1;

	stk->arr[--sp] = n;
	stk->sp = sp;
	return (int32_t)n;
}


static inline struct bt_stack *bt_stack_init(struct bt_stack *stk,
					     uint16_t capacity)
{
	if (unlikely(!stk)) {
		errno = -EINVAL;
		return NULL;
	}

	stk->arr = calloc_wrp(capacity, sizeof(*stk->arr));
	if (unlikely(!stk->arr))
		return NULL;

	stk->sp = capacity;
	stk->max_sp = capacity;
	return stk;
}


static inline void bt_stack_destroy(struct bt_stack *stk)
{
	if (stk->arr) {
		al64_free(stk->arr);
		stk->arr = NULL;
	}
}


static inline void bt_stack_test(__maybe_unused struct bt_stack * stk)
{
#ifndef NDEBUG
	uint16_t i, j, capacity = stk->max_sp;

	assert(capacity > 0);

	for (i = 0; i < capacity; i++) {
		/*
		 * Test stack is empty.
		 */
		assert(bt_stack_pop(stk) == -1);
		__asm__ volatile("":"+r"(stk)::"memory");
	}

	for (i = 0; i < capacity; i++) {
		/*
		 * Test fill the stack.
		 */
		assert(bt_stack_push(stk, i) == (int32_t)i);
		__asm__ volatile("":"+r"(stk)::"memory");
	}

	for (i = 0; i < capacity; i++) {
		/*
		 * Test stack is full.
		 */
		assert(bt_stack_push(stk, i) == -1);
		__asm__ volatile("":"+r"(stk)::"memory");
	}

	for (j = capacity - 1, i = 0; i < capacity; i++, j--) {
		/*
		 * Test stack is FIFO.
		 */
		assert(bt_stack_pop(stk) == j);
		__asm__ volatile("":"+r"(stk)::"memory");
	}

	for (i = 0; i < capacity; i++) {
		/*
		 * Test stack is empty.
		 */
		assert(bt_stack_pop(stk) == -1);
		__asm__ volatile("":"+r"(stk)::"memory");
	}

	pr_debug("bt_stack_test success!");
#endif
}


#endif /* #ifndef TEAVPN2__STACK_H */

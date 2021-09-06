// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__STACK_H
#define TEAVPN2__STACK_H

#include <stdint.h>
#include <emerg/emerg.h>
#include <teavpn2/common.h>


struct bt_stack {
	uint16_t		sp;
	uint16_t		max_sp;
	uint16_t		*arr;
};


static inline int32_t bt_stack_pop(struct bt_stack *stk)
{
	int32_t ret;
	uint16_t sp;

	if (BUG_ON(stk == NULL))
		return -1;

	sp = stk->sp;
	if (unlikely(sp == stk->max_sp))
		/* Stack is empty. */
		return -1;

	ret = (int32_t)stk->arr[++sp];
	stk->sp = sp;
	return ret;
}


static inline int32_t bt_stack_push(struct bt_stack *stk, uint16_t n)
{
	uint16_t sp;

	if (BUG_ON(stk == NULL))
		return -1;

	sp = stk->sp;
	if (unlikely(sp == 0))
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
	if (stk->arr)
		al64_free(stk->arr);
}


#endif /* #ifndef TEAVPN2__STACK_H */

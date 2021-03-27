// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/teavpn2/tstack.h
 *
 *  TCP slot stack.
 *
 *  This functionality is supposed to retrieve channel in O(1).
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__TSTACK_H
#define TEAVPN2__TSTACK_H

#include <stdlib.h>
#include <teavpn2/base.h>


#ifdef TSTACK_TEST
#  define inline_prod __no_inline
#else
#  define inline_prod inline
#endif

struct tstack {
	uint16_t	sp;
	uint16_t	max_sp;
	struct_pad(0, 4);
	uint16_t	*arr;
};


static inline_prod struct tstack *tss_init(struct tstack *stack,
					   uint16_t capacity)
{
	uint16_t *arr;

	arr = calloc(capacity, sizeof(*arr));
	if (unlikely(arr == NULL)) {
		int err = errno;
		stack->arr = NULL;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}

	stack->arr = arr;
	stack->sp = capacity;
	stack->max_sp = capacity;
	return stack;
}


static inline_prod uint16_t tss_count(struct tstack *stack)
{
	return stack->max_sp - stack->sp;
}


static inline_prod uint16_t tss_capacity(struct tstack *stack)
{
	return stack->max_sp;
}


static inline_prod bool tss_is_empty(struct tstack *stack)
{
	return tss_count(stack) == 0;
}


static inline_prod void tss_destroy(struct tstack *stack)
{
	free(stack->arr);
}


static inline_prod int32_t tss_push(struct tstack *stack, uint16_t data)
{
	uint16_t sp = stack->sp;

	if (unlikely(sp == 0)) {
		/* Stack is full */
		return -1;
	}

	stack->arr[--sp] = data;
	stack->sp = sp;
	return data;
}


static inline_prod int32_t tss_pop(struct tstack *stack)
{
	int32_t ret;
	uint16_t sp = stack->sp;
	uint16_t max_sp = stack->max_sp;

	if (unlikely(sp >= max_sp)) {
		/* Stack is empty */
		return -1;
	}

	ret = (int32_t)stack->arr[sp];
	stack->sp++;
	return ret;
}


#endif /* #ifndef TEAVPN2__TSTACK_H */

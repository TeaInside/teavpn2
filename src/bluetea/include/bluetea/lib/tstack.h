// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/lib/tstack.h
 *
 *  Stack library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__LIB__TSTACK_H
#define BLUETEA__LIB__TSTACK_H

#include <errno.h>
#include <stdlib.h>
#include <bluetea/base.h>


#ifdef TSTACK_TEST
#  define inline_prod __no_inline
#else
#  define inline_prod inline
#endif


struct tstack {
	uint32_t	sp;
	uint32_t	capacity;
	uint32_t	*arr;
};


static inline_prod struct tstack *tss_init(struct tstack *st, uint32_t capacity)
{
	uint32_t *arr;

	arr = calloc(capacity, sizeof(*arr));
	if (unlikely(arr == NULL)) {
		int err = errno;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}

	st->sp       = capacity; /* Stack pointer starts from high address */
	st->capacity = capacity;
	st->arr      = arr;
	return st;
}


static inline_prod uint32_t tss_count(struct tstack *st)
{
	uint32_t cap = st->capacity, sp = st->sp;

	/*
	 * Stack pointer must never be greater than the capacity.
	 */
	TASSERT(sp <= cap);
	return cap - sp;
}


static inline_prod int64_t tss_push(struct tstack *st, uint32_t val)
{
	uint32_t __maybe_unused cap = st->capacity;
	uint32_t sp = st->sp;

	/*
	 * Stack pointer must never be greater than the capacity.
	 */
	TASSERT(sp <= cap);

	if (unlikely(sp == 0)) {
		/* Stack if full */
		return -1;
	}

	st->arr[--sp] = val;
	st->sp = sp;
	return (int64_t)val;
}


static inline_prod int64_t tss_pop(struct tstack *st)
{
	int64_t ret;
	uint32_t cap = st->capacity, sp = st->sp;

	/*
	 * Stack pointer must never be greater than the capacity.
	 */
	TASSERT(sp <= cap);

	if (unlikely(sp == cap)) {
		/* Stack is empty */
		return -1;
	}

	ret = (int64_t)st->arr[sp++];
	st->sp = sp;
	return ret;
}


static inline_prod void tss_destroy(struct tstack *st)
{
	free(st->arr);
}


#endif /* #ifndef BLUETEA__LIB__TSTACK_H */

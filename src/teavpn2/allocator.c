// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <teavpn2/allocator.h>
#include <teavpn2/common.h>


static __always_inline void *mem_align(void *src, size_t size)
{
	void *ret;
	uint8_t shift;

	ret = (void *)(((uintptr_t)src + size) & ~(size - 1ul));
	shift = (uint8_t)((uintptr_t)ret - (uintptr_t)src);
	memcpy((void *)((uintptr_t)ret - 1ul), &shift, 1ul);

	assert(((uintptr_t)ret % size) == 0);

	return ret;
}


noinline void *al64_calloc(size_t nmemb, size_t size)
{
	void *orig;
	size_t real_size = 0;

	if (unlikely(__builtin_mul_overflow(nmemb, size, &real_size))) {
		errno = ENOMEM;
		return NULL;
	}

	orig = calloc(1u, real_size + 64ul);
	if (unlikely(!orig))
		return NULL;

	return mem_align(orig, 64ul);
}


noinline void *al64_malloc(size_t size)
{
	void *orig;

	orig = malloc(size + 64ul);
	if (unlikely(!orig))
		return NULL;

	return mem_align(orig, 64ul);
}


noinline void al64_free(void *user)
{
	void *orig;
	uint8_t shift;

	if (unlikely(!user))
		return;

	memcpy(&shift, (void *)((uintptr_t)user - 1ul), 1ul);
	orig = (void *)((uintptr_t)user - (uintptr_t)shift);
	free(orig);
}


noinline void *al64_realloc(void *user, size_t new_size)
{
	void *tmp;
	void *orig;
	uint8_t shift;

	if (unlikely(!user))
		return al64_malloc(new_size);

	memcpy(&shift, (void *)((uintptr_t)user - 1ul), 1ul);
	orig = (void *)((uintptr_t)user - (uintptr_t)shift);

	tmp = realloc(orig, new_size + 64ul);
	if (unlikely(!tmp))
		return NULL;

	return mem_align(tmp, 64ul);
}

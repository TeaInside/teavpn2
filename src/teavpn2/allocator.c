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


noinline void *al64_calloc(size_t nmemb, size_t size)
{
	void *orig;
	void *aligned;
	uint8_t shift;
	size_t real_size = 0;
	size_t extra_size = 63ul + sizeof(shift);

	if (unlikely(__builtin_mul_overflow(nmemb, size, &real_size))) {
		errno = EOVERFLOW;
		return NULL;
	}

	orig = calloc(1u, real_size + extra_size);
	if (unlikely(!orig))
		return NULL;

	aligned = (void *)(((uintptr_t)orig + extra_size) & ~63ul);
	shift   = (uint8_t)((uintptr_t)aligned - (uintptr_t)orig);
	memcpy((void *)((uintptr_t)aligned - 1ul), &shift, 1ul);

	assert(((uintptr_t)aligned % 64) == 0);
	return aligned;
}


noinline void *al64_malloc(size_t size)
{
	void *orig;
	void *aligned;
	uint8_t shift;
	size_t extra_size = 63ul + sizeof(shift);

	orig = malloc(size + extra_size);
	if (unlikely(!orig))
		return NULL;

	aligned = (void *)(((uintptr_t)orig + extra_size) & ~63ul);
	shift   = (uint8_t)((uintptr_t)aligned - (uintptr_t)orig);
	memcpy((void *)((uintptr_t)aligned - 1ul), &shift, 1ul);

	assert(((uintptr_t)aligned % 64) == 0);
	return aligned;
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
	void *aligned;
	uint8_t shift;
	size_t extra_size = 63ul + sizeof(shift);

	if (unlikely(!user))
		return al64_malloc(new_size);

	memcpy(&shift, (void *)((uintptr_t)user - 1ul), sizeof(shift));
	orig = (void *)((uintptr_t)user - (uintptr_t)shift);

	tmp = realloc(orig, new_size + extra_size);
	if (unlikely(!tmp))
		return NULL;

	orig    = tmp;
	aligned = (void *)(((uintptr_t)orig + extra_size) & ~63ul);
	shift   = (uint8_t)((uintptr_t)aligned - (uintptr_t)orig);
	memcpy((void *)((uintptr_t)aligned - 1ul), &shift, 1ul);

	assert(((uintptr_t)aligned % 64) == 0);
	return aligned;
}

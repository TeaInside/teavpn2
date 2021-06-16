// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/allocator.c
 *
 *  Printing functions
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <bluetea/base.h>
#include <teavpn2/allocator.h>


__no_inline void *al64_calloc(size_t nmemb, size_t size)
{
	void *user;
	size_t real_size = 0;

	if (unlikely(__builtin_umull_overflow(nmemb, size, &real_size))) {
		errno = EOVERFLOW;
		return NULL;
	}
	user = al64_malloc(real_size);
	memset(user, 0, real_size);
	return user;
}


__no_inline void *al64_malloc(size_t size)
{
	void *orig;
	void *aligned;
	uint8_t shift;

	size += 63ull + sizeof(shift);

	orig = malloc(size);
	if (unlikely(!orig))
		return NULL;

	aligned = (void *)(((uintptr_t)orig + 63ull + sizeof(shift)) & ~63ull);
	shift   = (uint8_t)((uintptr_t)aligned - (uintptr_t)orig);

	memcpy((void *)((uintptr_t)aligned - 1ull), &shift, sizeof(shift));
	return aligned;
}


__no_inline void al64_free(void *user)
{
	void *orig;
	uint8_t shift;

	if (unlikely(!user))
		return;

	memcpy(&shift, (void *)((uintptr_t)user - 1ull), sizeof(shift));
	orig = (void *)((uintptr_t)user - (uintptr_t)shift);
	free(orig);
}


__no_inline void *al64_realloc(void *user, size_t new_size)
{
	void *tmp;
	void *orig;
	void *aligned;
	uint8_t shift;

	if (unlikely(!user))
		return al64_malloc(new_size);

	memcpy(&shift, (void *)((uintptr_t)user - 1ull), sizeof(shift));
	orig = (void *)((uintptr_t)user - (uintptr_t)shift);

	new_size += 63ull + sizeof(shift);

	tmp = realloc(orig, new_size);
	if (unlikely(!tmp))
		return NULL;

	orig    = tmp;
	aligned = (void *)(((uintptr_t)orig + 63ull + sizeof(shift)) & ~63ull);
	shift   = (uint8_t)((uintptr_t)aligned - (uintptr_t)orig);

	memcpy((void *)((uintptr_t)aligned - 1ull), &shift, sizeof(shift));
	return aligned;
}

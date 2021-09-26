// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__ALLOCATOR_H
#define TEAVPN2__ALLOCATOR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <teavpn2/compiler_attributes.h>

extern void *al64_calloc(size_t nmemb, size_t size);
extern __malloc void *al64_malloc(size_t size);
extern void al64_free(void *user);
extern void *al64_realloc(void *user, size_t new_size);

static inline void *al4096_malloc_mmap(size_t size)
{
	void *ret;

	ret = mmap(NULL, size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret == MAP_FAILED)
		return NULL;

	return ret;
}


static inline void al4096_free_munmap(void *user, size_t size)
{
	if (user != NULL)
		munmap(user, size);
}

#endif /* #ifndef TEAVPN2__ALLOCATOR_H */

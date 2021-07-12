// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/allocator.h
 *
 *  Allocator header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef TEAVPN2__ALLOCATOR_H
#define TEAVPN2__ALLOCATOR_H

#include <stdlib.h>

extern void *al64_calloc(size_t nmemb, size_t size);
extern void *al64_malloc(size_t size);
extern void al64_free(void *user);
extern void *al64_realloc(void *user, size_t new_size);

#include <errno.h>
#include <teavpn2/print.h>

static inline void *al64_calloc_wrp(size_t nmemb, size_t size)
{
	void *ret = al64_calloc(nmemb, size);
	if (unlikely(ret == NULL)) {
		int err = errno;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}
	return ret;
}

#endif /* #ifndef TEAVPN2__ALLOCATOR_H */

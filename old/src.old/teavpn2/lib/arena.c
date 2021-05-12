// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/lib/arena.c
 *
 *  Arena memory manager for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <teavpn2/base.h>
#include <teavpn2/lib/arena.h>


static char   *__ar_addr = NULL;
static size_t __ar_size  = 0;
static size_t __ar_pos   = 0;


void ar_init(char *ar, size_t size)
{
	__ar_addr = ar;
	__ar_size = size;
	__ar_pos = 0;
}


size_t ar_unused_size(void)
{
	return __ar_size - __ar_pos;
}


static __always_inline void *internal_ar_alloc(size_t len)
{
	char *ret = &__ar_addr[__ar_pos];

	__ar_pos += len;
	TASSERT(__ar_size > __ar_pos);
	return (void *)ret;
}


void *ar_alloc(size_t len)
{
	return internal_ar_alloc(len);
}


void *ar_strdup(const char *str)
{
	char   *ret;
	size_t len = strlen(str);

	ret = internal_ar_alloc(len + 1);
	ret[len] = '\0';
	return memcpy(ret, str, len);
}


void *ar_strndup(const char *str, size_t inlen)
{
	char   *ret;
	size_t len = strnlen(str, inlen);

	ret = internal_ar_alloc(len + 1);
	ret[len] = '\0';
	return memcpy(ret, str, len);
}

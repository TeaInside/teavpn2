// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/arena.c
 *
 *  Arena library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#include <bluetea/lib/arena.h>


static void *__ar_buf = NULL;
static size_t __ar_size = 0;
static size_t __ar_used = 0;


__no_inline int ar_init(void *ar_buf, size_t size)
{
	uintptr_t uptr = (uintptr_t)ar_buf;

	if ((size == 0) || ((size & 0xfull) != 0)) {
		/*
		 * Size is not multiple of 16
		 */
		return -EINVAL;
	}

	if ((uptr & 0xfull) != 0) {
		/*
		 * Pointer is not 16 byte aligned
		 */
		return -EINVAL;
	}

	__ar_buf  = ar_buf;
	__ar_size = size;
	__ar_used = 0;
	return 0;
}


static inline size_t internal_ar_capacity(void)
{
	return __ar_size - __ar_used;
}


__no_inline size_t ar_capacity(void)
{
	return internal_ar_capacity();
}


static inline void *internal_ar_alloc(size_t len)
{
	void *ret;
	size_t capacity = internal_ar_capacity();

	len = (len + 0xfull) & (~0xfull);
	if (unlikely(capacity < len)) {
		errno = ENOMEM;
		return NULL;
	}

	ret = (char *)__ar_buf + __ar_used;
	__ar_used += len;
	return ret;
}


__no_inline void *ar_alloc(size_t len)
{
	return internal_ar_alloc(len);
}


__no_inline void *ar_strdup(const char *str)
{
	char   *ret;
	size_t len = strlen(str);

	ret = internal_ar_alloc(len + 1);
	if (unlikely(ret == NULL))
		return NULL;
	ret[len] = '\0';
	return memcpy(ret, str, len);
}


__no_inline void *ar_strndup(const char *str, size_t inlen)
{
	char   *ret;
	size_t len = strnlen(str, inlen);

	ret = internal_ar_alloc(len + 1);
	if (unlikely(ret == NULL))
		return NULL;
	ret[len] = '\0';
	return memcpy(ret, str, len);
}

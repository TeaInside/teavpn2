// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/include/bluetea/lib/arena.h
 *
 *  String library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef BLUETEA__LIB__STRING_H
#define BLUETEA__LIB__STRING_H

#include <ctype.h>
#include <bluetea/base.h>

extern char *escapeshellarg(char *alloc, const char *str, size_t len,
			    size_t *res_len);

extern char *strtrim(char *str);
extern char *strtriml(char *str, size_t len);

extern char *strtrim_move(char *str);
extern char *strtriml_move(char *str, size_t len);

extern size_t htmlspecialchars(char *__restrict__ out, size_t outlen,
			       const char *__restrict__ in);

extern size_t htmlspecialcharsl(char *__restrict__ out, size_t outlen,
				const char *__restrict__ in, size_t inlen);

extern char *trunc_str(char *str, size_t n);

#if 0
inline static bool is_ws(char c)
{
	return (c == ' ') || (c == '\n') || (c == '\t') || (c == '\v') ||
		(c == '\r') || (c == '\f');
}
#endif

#define is_ws(c) isspace((unsigned char)(c))


__always_inline static void *short_memcpy(void *__restrict__ dst,
					  const void *__restrict__ src,
					  uint8_t len)
{
	volatile uint8_t *cdst = (uint8_t *)dst;
	volatile const uint8_t *csrc = (const uint8_t *)src;

	while (len--)
		*cdst++ = *csrc++;

	return dst;
}


static __always_inline char *sane_strncpy(char * __restrict__ dest,
					  const char * __restrict__ src,
					  size_t n)
{
	dest = strncpy(dest, src, n - 1);
	dest[n - 1] = '\0';
	return dest;
}


#endif /* #ifndef BLUETEA__LIB__STRING_H */

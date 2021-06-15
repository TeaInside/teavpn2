// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/lib/string.h
 *
 *  String library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__LIB__STRING_H
#define BLUETEA__LIB__STRING_H

#include <string.h>
#include <bluetea/base.h>


char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len);


/*
 * Trim a null terminated C string.
 *
 * - The length of `char *str` must be known be the caller.
 * - `size_t *res_len` returns the length of trimmed string.
 * - This trim function doesn't shift any char.
 * - This function returns a pointer to the trimmed position.
 */
char *trim_len(char *str, size_t len, size_t *res_len);

/*
 * Same as trim_len, but may shift the string on memory.
 */
char *trim_len_cpy(char *head, size_t len, size_t *res_len);

/*
 * Same as trim_len, but implicit length.
 */
char *trim(char *str);

/*
 * Same as trim_len_cpy, but implicit length.
 */
char *trim_cpy(char *str);


char *trunc_str(char *str, size_t n);
void *memzero_explicit(void *s, size_t n);
int memcmp_explicit(const void *s1, const void *s2, size_t n);
char *urlencode(char *alloc, const char *s, size_t len, bool raw);
size_t htmlspecialchars(char * restrict _output, size_t outlen,
			const char * restrict _input, size_t inlen);



inline static char *sane_strncpy(char * __restrict__ dest,
				 const char * __restrict__ src,
				 size_t n)
{
	dest = strncpy(dest, src, n - 1);
	dest[n - 1] = '\0';
	return dest;
}


static inline bool is_ws(char c)
{
	return (c == ' ') || (c == '\n') || (c == '\t') || (c == '\r') ||
		(c == '\v');
}


#endif /* #ifndef BLUETEA__LIB__STRING_H */

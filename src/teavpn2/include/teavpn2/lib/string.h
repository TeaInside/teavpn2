
#ifndef TEAVPN2__LIB__STRING_H
#define TEAVPN2__LIB__STRING_H

#include <stddef.h>
#include <string.h>


char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len);
char *trim_len(char *head, size_t len, size_t *res_len);
char *trim_len_cpy(char *head, size_t len, size_t *res_len);
char *trim(char *str);
char *trim_cpy(char *str);
char *trunc_str(char *str, size_t n);
void *memzero_explicit(void *s, size_t n);
int memcmp_explicit(const void *s1, const void *s2, size_t n);

#if !defined(__clang__) && defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif

inline static char *sane_strncpy(char * __restrict__ dest,
				 const char * __restrict__ src,
				 size_t n)
{
	dest = strncpy(dest, src, n - 1);
	dest[n - 1] = '\0';
	return dest;
}

#if !defined(__clang__) && defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif

#endif /* #ifndef TEAVPN2__LIB__STRING_H */

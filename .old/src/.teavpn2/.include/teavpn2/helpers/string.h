
#ifndef __TEAVPN2__HELPERS__STRING_H
#define __TEAVPN2__HELPERS__STRING_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <teavpn2/global/common.h>

/**
 * @param char x
 * @return char
 */
static __always_inline char my_tolower(char x)
{
	return ('A' <= x && x <= 'Z') ? x + 32 : x;
}


/**
 * @param char x
 * @return char
 */
static __always_inline char my_toupper(char x)
{
	return ('a' <= x && x <= 'z') ? x - 32 : x;
}

char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len);
char *trim(char *str);
char *trim_cpy(char *str);
char *trim_len(char *head, size_t len, size_t *res_len);
char *trim_len_cpy(char *head, size_t len, size_t *res_len);
char *trunc_str(char *str, size_t n);

#endif /* #ifndef __TEAVPN2__HELPERS__STRING_H */

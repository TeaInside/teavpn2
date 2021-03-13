
#ifndef TEAVPN2__LIB__STRING_H
#define TEAVPN2__LIB__STRING_H

#include <stddef.h>


char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len);
char *trim_len(char *head, size_t len, size_t *res_len);
char *trim_len_cpy(char *head, size_t len, size_t *res_len);
char *trim(char *str);
char *trim_cpy(char *str);
char *trunc_str(char *str, size_t n);
void *memzero_explicit(void *s, size_t n);

#endif /* #ifndef TEAVPN2__LIB__STRING_H */

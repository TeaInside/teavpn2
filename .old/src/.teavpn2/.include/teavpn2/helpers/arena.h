
#ifndef __TEAVPN2__HELPERS__ARENA_H
#define __TEAVPN2__HELPERS__ARENA_H

#include <stddef.h>

void ar_init(char *ar, size_t ar_size);
size_t ar_unused_size();
void *ar_alloc(size_t len);
void *ar_strdup(const char *str);
void *ar_strndup(const char *str, size_t inlen);

#endif /* #ifndef __TEAVPN2__HELPERS__ARENA_H */

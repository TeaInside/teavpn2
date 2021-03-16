// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/include/lib/arena.h
 *
 *  Arena header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__LIB__ARENA_H
#define TEAVPN2__LIB__ARENA_H

#include <stddef.h>


void ar_init(char *ar, size_t size);
size_t ar_unused_size(void);
void *ar_alloc(size_t len);
void *ar_strdup(const char *str);
void *ar_strndup(const char *str, size_t inlen);

#endif /* #ifndef TEAVPN2__LIB__ARENA_H */

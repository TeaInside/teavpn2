// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/lib/arena.h
 *
 *  Arena library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef BLUETEA__LIB__ARENA_H
#define BLUETEA__LIB__ARENA_H

#include <bluetea/base.h>

int ar_init(void *ar_buf, size_t size);
size_t ar_capacity(void);
void *ar_alloc(size_t len);
void *ar_strdup(const char *str);
void *ar_strndup(const char *str, size_t inlen);


#endif /* #ifndef BLUETEA__LIB__ARENA_H */

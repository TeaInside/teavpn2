// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/include/bluetea/lib/arena.h
 *
 *  Arena library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef BLUETEA__LIB__ARENA_H
#define BLUETEA__LIB__ARENA_H

#include <bluetea/base.h>

extern int ar_init(void *ar_buf, size_t size);
extern size_t ar_capacity(void);
extern void *ar_alloc(size_t len);
extern void *ar_strdup(const char *str);
extern void *ar_strndup(const char *str, size_t inlen);

#endif /* #ifndef BLUETEA__LIB__ARENA_H */

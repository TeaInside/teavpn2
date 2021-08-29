// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/include/bluetea/base.h
 *
 *  Base header for BlueTea C framework
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__BASE_H
#define BLUETEA__BASE_H

#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <inttypes.h>

#include <bluetea/vt_hexdump.h>

#define BT_ASSERT(EXPR) assert(EXPR)

#define likely(EXPR)   __builtin_expect((bool)(EXPR), 1)
#define unlikely(EXPR) __builtin_expect((bool)(EXPR), 0)

#ifndef static_assert
#  define static_assert(EXPR, ASSERT) _Static_assert((EXPR), ASSERT)
#endif

#ifndef offsetof
#  define offsetof(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef member_size
#  define member_size(type, member) sizeof(((type *)0)->member)
#endif

#ifndef ARRAY_SIZE
#  define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#ifndef __maybe_unused
#  define __maybe_unused __attribute__((unused))
#endif

#ifndef __inline
#  define __inline inline
#endif

#ifndef __always_inline
#  define __always_inline __inline __attribute__((always_inline))
#endif

#ifndef __no_inline
#  define __no_inline __attribute__((noinline))
#endif

#ifndef __no_return
#  define __no_return __attribute__((noreturn))
#endif


#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


#if __has_attribute(__fallthrough__)
#  define fallthrough __attribute__((__fallthrough__))
#else
#  define fallthrough do {} while (0)  /* fallthrough */
#endif


#define struct_pad(N, SIZE) uint8_t __pad__##N[SIZE]


static_assert(sizeof(char) == 1, "Bad sizeof(char)");
static_assert(sizeof(short) == 2, "Bad sizeof(short)");
static_assert(sizeof(int) == 4, "Bad sizeof(int)");
static_assert(sizeof(unsigned char) == 1, "Bad sizeof(unsigned char)");
static_assert(sizeof(unsigned short) == 2, "Bad sizeof(unsigned short)");
static_assert(sizeof(unsigned int) == 4, "Bad sizeof(unsigned int)");
static_assert(sizeof(bool) == 1, "Bad sizeof(bool)");

static_assert(sizeof(int8_t) == 1, "Bad sizeof(int8_t)");
static_assert(sizeof(uint8_t) == 1, "Bad sizeof(uint8_t)");

static_assert(sizeof(int16_t) == 2, "Bad sizeof(int16_t)");
static_assert(sizeof(uint16_t) == 2, "Bad sizeof(uint16_t)");

static_assert(sizeof(int32_t) == 4, "Bad sizeof(int32_t)");
static_assert(sizeof(uint32_t) == 4, "Bad sizeof(uint32_t)");

static_assert(sizeof(int64_t) == 8, "Bad sizeof(int64_t)");
static_assert(sizeof(uint64_t) == 8, "Bad sizeof(uint64_t)");

/* We only support 32-bit and 64-bit pointer size. */
static_assert((sizeof(void *) == 8) || (sizeof(void *) == 4),
	      "Bad sizeof(void *)");

#endif /* #ifndef BLUETEA__BASE_H */

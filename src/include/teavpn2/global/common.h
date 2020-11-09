
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

#define likely(EXPR)   __builtin_expect(!!(EXPR), 1)
#define unlikely(EXPR) __builtin_expect(!!(EXPR), 0)
#define STATIC_ASSERT(EXPR, ASSERT) _Static_assert ((EXPR), ASSERT)

#ifndef OFFSETOF
#  define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#define err_printf(...) printf(__VA_ARGS__)
#define dbg_printf(TYPE, ...) printf(__VA_ARGS__)

typedef enum __attribute__((packed))
{
  SOCK_TCP = 1,
  SOCK_UDP = 2
} sock_type;


STATIC_ASSERT(sizeof(sock_type) == 1, "sizeof(sock_type) must be 1");

#endif

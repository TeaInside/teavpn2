
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <stdio.h>

#if defined(__linux__)
#  include <arpa/inet.h>
#  include <linux/types.h>
#else

typedef uint64_t __be64;
typedef uint32_t __be32;
typedef uint16_t __be16;

#endif

#define likely(EXPR)   __builtin_expect((EXPR), 1)
#define unlikely(EXPR) __builtin_expect((EXPR), 0)
#define STATIC_ASSERT(EXPR, ASSERT) _Static_assert ((EXPR), ASSERT)

#ifndef OFFSETOF
#  define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef INET_ADDRSTRLEN
#  define IPV4L (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4L (INET_ADDRSTRLEN)
#endif

#ifndef INET6_ADDRSTRLEN
#  define IPV6L (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6L (INET6_ADDRSTRLEN)
#endif

#define err_printf(FMT, ...) printf(FMT "\n", ##__VA_ARGS__)
#define dbg_printf(TYPE, FMT, ...) printf(FMT "\n", ##__VA_ARGS__)
#define log_printf(VERBOSE_LVL, FMT, ...) printf(FMT "\n", ##__VA_ARGS__)

typedef enum __attribute__((packed))
{
  SOCK_TCP = 1,
  SOCK_UDP = 2
} sock_type;


STATIC_ASSERT(sizeof(int)       == 4, "sizeof(int) must be 4");
STATIC_ASSERT(sizeof(char)      == 1, "sizeof(char) must be 1");
STATIC_ASSERT(sizeof(short)     == 2, "sizeof(short) must be 2");
STATIC_ASSERT(sizeof(sock_type) == 1, "sizeof(sock_type) must be 1");

#endif



#ifndef __TEAVPN2__GLOBAL__COMMON_H
#define __TEAVPN2__GLOBAL__COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define likely(EXPR)   __builtin_expect((EXPR), 1)
#define unlikely(EXPR) __builtin_expect((EXPR), 0)
#define STATIC_ASSERT(EXPR, ASSERT) _Static_assert((EXPR), ASSERT)

#ifndef OFFSETOF
#  define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef INET_ADDRSTRLEN
#  define IPV4LEN (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4LEN (INET_ADDRSTRLEN)
#endif

#ifndef INET6_ADDRSTRLEN
#  define IPV6LEN (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6LEN (INET6_ADDRSTRLEN)
#endif

#define pr_error(...) printf(__VA_ARGS__)

typedef enum {
	SOCK_TCP = 1,
	SOCK_UDP = 2
} sock_type;

#endif /* #ifndef __TEAVPN2__GLOBAL__COMMON_H */

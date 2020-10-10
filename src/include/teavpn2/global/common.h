
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define DATA_SIZE (6144)

#ifndef OFFSETOF
#  define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef likely
#  define likely(EXPR)   __builtin_expect((EXPR), 1)
#endif

#ifndef unlikely
#  define unlikely(EXPR) __builtin_expect((EXPR), 0)
#endif

#include <teavpn2/global/debug.h>
#include <teavpn2/global/helpers.h>

typedef enum {
  SOCK_TCP,
  SOCK_UDP
} socket_type;

#endif

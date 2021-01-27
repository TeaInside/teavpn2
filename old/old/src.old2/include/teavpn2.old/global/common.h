
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

#define ST_ASSERT(cond) _Static_assert(cond, #cond)

#define STATIC_ASSERT(COND,MSG) \
  typedef char static_assertion_##MSG[(!!(COND))*2-1]

#define COMPILE_TIME_ASSERT3(X,L) \
  STATIC_ASSERT(X,static_assertion_at_line_##L)

#define COMPILE_TIME_ASSERT2(X,L) COMPILE_TIME_ASSERT3(X,L)

#define COMPILE_TIME_ASSERT(X)    COMPILE_TIME_ASSERT2(X,__LINE__)


#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')
#define VT_HEXDUMP(PTR, SIZE)                               \
  do {                                                      \
    size_t i, j, k = 0, l, size = (SIZE);                   \
    unsigned char *ptr = (unsigned char *)(PTR);            \
    printf("============ VT_HEXDUMP ============\n");       \
    printf("File\t\t: %s:%d\n", __FILE__, __LINE__);        \
    printf("Function\t: %s()\n", __FUNCTION__);             \
    printf("Address\t\t: 0x%016lx\n", (uintptr_t)ptr);      \
    printf("Dump size\t: %ld bytes\n", (size));             \
    printf("\n");                                           \
    for (i = 0; i < ((size/16) + 1); i++) {                 \
      printf("0x%016lx|  ", (uintptr_t)(ptr + i * 16));     \
      l = k;                                                \
      for (j = 0; (j < 16) && (k < size); j++, k++) {       \
        printf("%02x ", ptr[k]);                            \
      }                                                     \
      while (j++ < 16) printf("   ");                       \
      printf(" |");                                         \
      for (j = 0; (j < 16) && (l < size); j++, l++) {       \
        printf("%c", CHDOT(ptr[l]));                        \
      }                                                     \
      printf("|\n");                                        \
    }                                                       \
    printf("=====================================\n");      \
  } while(0)

#include <teavpn2/global/debug.h>
#include <teavpn2/global/helpers.h>

typedef enum {
  SOCK_TCP,
  SOCK_UDP
} socket_type;

#endif

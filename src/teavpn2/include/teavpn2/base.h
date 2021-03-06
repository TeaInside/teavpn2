
#ifndef TEAVPN2__BASE_H
#define TEAVPN2__BASE_H

#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <inttypes.h>
#include <teavpn2/print.h>
#include <teavpn2/vt_hexdump.h>


#define TASSERT(EXPR) assert(EXPR)

#define likely(EXPR)   __builtin_expect(!!(EXPR), 1)
#define unlikely(EXPR) __builtin_expect(!!(EXPR), 0)

#ifndef static_assert
#  define static_assert(EXPR, ASSERT) _Static_assert((EXPR), ASSERT)
#endif

#ifndef offsetof
#  define offsetof(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef INET_ADDRSTRLEN
#  define IPV4_L (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4_L (INET_ADDRSTRLEN)
#endif

#ifndef INET6_ADDRSTRLEN
#  define IPV6_L (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6_L (INET6_ADDRSTRLEN)
#endif

#define IPV4_SL (IPV4_L + 8) /* For safer size */
#define IPV6_SL (IPV6_L + 8) /* For safer size */

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
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

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

#if __has_attribute(__fallthrough__)
#  define fallthrough __attribute__((__fallthrough__))
#else
#  define fallthrough do {} while (0)  /* fallthrough */
#endif


#define struct_pad(N, SIZE) uint8_t __##N[SIZE]


typedef enum {
	SOCK_TCP = 0,
	SOCK_UDP = 1
} sock_type;

int print_license(unsigned short i);
void teavpn_print_version(void);

#define TEAVPN2_VERSION VERSION "." PATCHLEVEL "." SUBLEVEL EXTRAVERSION

#endif /* #ifndef TEAVPN2__BASE_H */

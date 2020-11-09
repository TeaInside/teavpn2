
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

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

#include <teavpn2/global/log.h>
#include <teavpn2/global/types.h>
#include <teavpn2/global/helpers.h>


#endif

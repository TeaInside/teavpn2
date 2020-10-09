
#ifndef TEAVPN2__GLOBAL__DEBUG_H
#define TEAVPN2__GLOBAL__DEBUG_H

#include <stdint.h>

#ifndef DONT_EXTERN_DEBUG_VERBOSE_LEVEL
extern uint8_t verbose_level;
#endif

#ifndef MAX_DEBUG_LEVEL
#  define MAX_DEBUG_LEVEL (5)
#endif

#ifndef DEFAULT_DEBUG_VERBOSE_LEVEL
#  define DEFAULT_DEBUG_VERBOSE_LEVEL (5)
#endif

void
__internal_debug_log(const char *msg, ...);

#define debug_log(VLEVEL, Y, ...) do {           \
    const uint8_t __vlevel = (VLEVEL);           \
    if (__vlevel <= MAX_DEBUG_LEVEL) {           \
      if (__vlevel <= verbose_level) {           \
        __internal_debug_log(Y, ##__VA_ARGS__);  \
      }                                          \
    }                                            \
  } while (0)

#endif

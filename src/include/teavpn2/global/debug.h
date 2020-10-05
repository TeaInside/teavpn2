

#ifndef TEAVPN2__GLOBAL__DEBUG_H
#define TEAVPN2__GLOBAL__DEBUG_H

#include <stdint.h>

#ifndef DONT_EXTERN_VERBOSE_LEVEL
extern uint8_t verbose_level;
#endif

#define MAX_DEBUG_LEVEL (100)

__attribute__((force_align_arg_pointer))
uint8_t __internal_debug_log(const char *msg, ...);

#define debug_log(VLEVEL, Y, ...) do {           \
    const uint16_t __vlevel = VLEVEL;            \
    if (__vlevel <= MAX_DEBUG_LEVEL) {           \
      if (__vlevel <= verbose_level) {           \
        __internal_debug_log(Y, ##__VA_ARGS__);  \
      }                                          \
    }                                            \
  } while (0)

#endif

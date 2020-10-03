

#ifndef TEAVPN2__GLOBAL__DEBUG_H
#define TEAVPN2__GLOBAL__DEBUG_H

#include <stdint.h>

#ifndef DONT_EXTERN_VERBOSE_LEVEL
extern uint8_t verbose_level;
#endif

__attribute__((force_align_arg_pointer))
uint8_t __internal_debug_log(const char *msg, ...);

#define debug_log(VLEVEL, Y, ...) \
  if (VLEVEL <= verbose_level) {__internal_debug_log(Y, ##__VA_ARGS__);}

#endif

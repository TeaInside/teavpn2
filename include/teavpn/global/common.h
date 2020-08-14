
#ifndef TEAVPN__GLOBAL__COMMON_H
#define TEAVPN__GLOBAL__COMMON_H

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

int __teavpn_debug_log(const char *format, ...);

#ifndef GLOBAL_LOGGER_C
extern uint8_t __debug_log_level;
#endif

#define debug_log(LEVEL, ...)                \
  ( (__debug_log_level >= ((uint8_t)LEVEL))  \
    ? __teavpn_debug_log(__VA_ARGS__)        \
    : 0                                      \
  )

#endif

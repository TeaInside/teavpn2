
#ifndef TEAVPN__GLOBAL__COMMON_H
#define TEAVPN__GLOBAL__COMMON_H

#include <stdint.h>

void __internal_teavpn_debug_log(const char *format, ...);

#ifndef TEAVPN_DEBUGGER_FILE
  int8_t teavpn_verbose_level;
#endif

#define debug_log(VLEVEL, ...) \
  if (teavpn_verbose_level <= VLEVEL) \
    teavpn_debug_log(const char *format, ...)

#endif

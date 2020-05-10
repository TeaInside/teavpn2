
#ifndef TEAVPN__GLOBAL__DEBUGGER_H
#define TEAVPN__GLOBAL__DEBUGGER_H

#include <stdio.h>

void __internal_teavpn_debug_log(const char *format, ...);

#ifndef TEAVPN_DEBUGGER_FILE
  int8_t teavpn_verbose_level;
#endif

#define error_log(FORMAT, ...) printf(FORMAT"\n", ##__VA_ARGS__);

#ifdef TEAVPN_DEBUG

#define debug_log(VLEVEL, FORMAT, ...) \
  if (teavpn_verbose_level <= VLEVEL) \
    __internal_teavpn_debug_log(FORMAT"\n", ##__VA_ARGS__)

#else

#define debug_log(VLEVEL, ...)

#endif

#endif

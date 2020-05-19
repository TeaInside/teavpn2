
#ifndef TEAVPN__GLOBAL__DEBUGGER_H
#define TEAVPN__GLOBAL__DEBUGGER_H

#include <stdio.h>

void __internal_teavpn_debug_log(const char *format, ...);


#define error_log(FORMAT, ...) printf(FORMAT"\n", ##__VA_ARGS__);

#ifdef TEAVPN_DEBUG
  #define TEAVPN_VERBOSE_LEVEL 8
#else
  #define TEAVPN_VERBOSE_LEVEL 2
#endif

#define debug_log(VLEVEL, FORMAT, ...) \
  if (TEAVPN_VERBOSE_LEVEL <= VLEVEL) \
    __internal_teavpn_debug_log(FORMAT"\n", ##__VA_ARGS__)

#endif

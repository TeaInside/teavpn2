
#ifndef TEAVPN__GLOBAL__DEBUGGER_H
#define TEAVPN__GLOBAL__DEBUGGER_H

void __internal_teavpn_debug_log(const char *format, ...);

#ifndef TEAVPN_DEBUGGER_FILE
  int8_t teavpn_verbose_level;
#endif

#ifdef TEAVPN_DEBUG

#define debug_log(VLEVEL, ...) \
  if (teavpn_verbose_level <= VLEVEL) \
    teavpn_debug_log(const char *format, ...)

#else

#define debug_log(VLEVEL, ...)

#endif

#endif

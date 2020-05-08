
#include <stdio.h>
#include <stdarg.h>

#define TEAVPN_DEBUGGER_FILE 1

#include <teavpn2/global/common.h>

int8_t verbose_level;

void __internal_teavpn_debug_log(const char *format, ...)
{
  va_list argp;
  va_start(argp, format);
  vfprintf(stdout, format, argp);
  va_end(argp);
  fflush(stdout);
}

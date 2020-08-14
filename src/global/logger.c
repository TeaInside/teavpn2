
#define GLOBAL_LOGGER_C

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <teavpn/global/common.h>

uint8_t __debug_log_level = 5;

int __teavpn_debug_log(const char *format, ...)
{
  int ret;
  va_list ap;
  register char *formatted;
  time_t unixnow = time(NULL);

  va_start(ap, format);

  formatted = asctime(localtime(&unixnow));
  formatted[strlen(formatted) - 1] = '\0';

  ret  = printf("[%s] ", formatted);
  ret += vprintf(format, ap);
  ret += printf("\n");

  fflush(stdout);

  va_end(ap);
  return ret;
}


int __teavpn_error_log(const char *format, ...)
{
  int ret;
  va_list ap;
  register char *formatted;
  time_t unixnow = time(NULL);

  va_start(ap, format);

  formatted = asctime(localtime(&unixnow));
  formatted[strlen(formatted) - 1] = '\0';

  ret = fprintf(stderr, "\n");

  fflush(stderr);

  va_end(ap);
  return ret;
}

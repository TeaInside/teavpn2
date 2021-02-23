
#include <time.h>
#include <stdio.h>
#include <stdarg.h>

#define DONT_EXTERN_DEBUG_VERBOSE_LEVEL 1

extern "C" {

#include <teavpn2/global/debug.h>

uint8_t __debug_verbose_level = DEFAULT_DEBUG_VERBOSE_LEVEL;


void
__internal_debug_log(const char *msg, ...)
{
  va_list argp;
  time_t rawtime;
  struct tm *timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);
  char *time = asctime(timeinfo);
  time[24] = '\0';

  va_start(argp, msg);
  fprintf(stdout, "[%s]: ", time);
  vfprintf(stdout, msg, argp);
  fprintf(stdout, "\n");
  va_end(argp);
  fflush(stdout);
}

}
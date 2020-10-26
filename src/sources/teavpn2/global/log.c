
#include <time.h>
#include <stdio.h>

#define DONT_EXTERN_LOG_VARS 1

#include <teavpn2/global/log.h>


FILE    **_log_res      = NULL;
uint8_t _log_res_c      = 0;
uint8_t _dbg_log_level  = DEFAULT_DEBUG_LOG_LEVEL;


/** 
 * @param const char *msg
 * @param va_list    argp
 * @return void
 */
void
_tvpn_internal_log(const char *msg, ...)
{
  uint8_t i = _log_res_c;

  char       *strtime;
  time_t     rawtime;
  struct tm  *timeinfo;


  time(&rawtime);
  timeinfo    = localtime(&rawtime);
  strtime     = asctime(timeinfo);
  strtime[24] = '\0';


  while (i--) {
    FILE       *stream = _log_res[i];

    va_list argp;
    va_start(msg, argp);
    fprintf(stream, "[%s]: ", strtime);
    vfprintf(stream, msg, argp);
    fprintf(stream, "\n");
    va_end(argp);
  }
}

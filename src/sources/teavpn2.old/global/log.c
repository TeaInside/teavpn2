
#include <time.h>
#include <stdio.h>

#define DONT_EXTERN_LOG_VARS 1

#include <teavpn2/global/log.h>

FILE    **_log_res      = NULL;
uint8_t _log_res_c      = 0;
uint8_t _dbg_log_level  = DEFAULT_DEBUG_LOG_LEVEL;


/**
 * @param FILE *stream
 * @return void
 */
void
tvpn_add_log_stream(FILE *stream)
{
  FILE **log_res = _log_res;

  if (log_res == NULL) {
    log_res = (FILE **)malloc(sizeof(FILE *));
  } else {
    log_res = (FILE **)realloc(log_res,
                               sizeof(FILE *) *
                               (_log_res_c + 1));
  }

  if (log_res == NULL) {
    printf("Error: Cannot allocate memory\n");
    free(_log_res);
    exit(0);
    return;
  }

  log_res[_log_res_c] = stream;
  _log_res            = log_res;
  _log_res_c++;
}


/**
 * @return void
 */
void
tvpn_clean_log_stream()
{
  free(_log_res);
  _log_res   = NULL;
  _log_res_c = 0;
}


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
    FILE *stream = _log_res[i];

    va_list argp;
    va_start(argp, msg);
    fprintf(stream, "[%s]: ", strtime);
    vfprintf(stream, msg, argp);
    fprintf(stream, "\n");
    va_end(argp);
  }
}

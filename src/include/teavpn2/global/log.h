
#ifndef TEAVPN2__GLOBAL__LOG_H
#define TEAVPN2__GLOBAL__LOG_H


#include <stdarg.h>

#include <teavpn2/global/types.h>
#include <teavpn2/global/common.h>

#define DEFAULT_DEBUG_LOG_LEVEL (5)
#define MAX_DEBUG_LEVEL         (5)

void
_tvpn_internal_log(const char *msg, ...);

extern FILE    **_log_res;
extern uint8_t _log_res_c;
extern uint8_t _dbg_log_level;

#define debug_log(VLEVEL, Y, ...) do {              \
    const uint8_t __vlevel = (VLEVEL);              \
    if ((__vlevel) <= (MAX_DEBUG_LEVEL)) {          \
      if ((__vlevel) <= (_dbg_log_level)) {         \
        _tvpn_internal_log(Y, ##__VA_ARGS__);       \
      }                                             \
    }                                               \
  } while (0)


#endif

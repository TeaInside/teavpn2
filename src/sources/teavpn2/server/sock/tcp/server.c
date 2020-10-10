
#include <teavpn2/server/common.h>

#if defined(__linux__)
#  include "server/linux.h"
#else
#  error "Compiler is not supported!"
#endif

/**
 * @param server_cfg *config
 * @return int
 */
int
tvpn_server_tcp_run(server_cfg *config)
{
  return __internal_tvpn_server_tcp_run(config);
}

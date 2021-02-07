
#include <teavpn2/client/common.h>
#include <teavpn2/global/packet.h>

#if defined(__linux__)
#  include "client/linux.h"
#else 
#  error "Compiler is not supported!"
#endif

/**
 * @param client_cfg *config
 * @return int
 */
int
tvpn_client_tcp_run(client_cfg *config)
{
  return __internal_tvpn_client_tcp_run(config);
}

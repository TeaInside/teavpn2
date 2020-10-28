

#include <teavpn2/server/common.h>
#include <teavpn2/server/tcp.h>

srv_tcp *g_server;

#define RACT(EXPR) (unlikely((state.stop) || (EXPR)))

#include "platform/tcp_init.h"
#include "platform/tcp_clean_up.h"

/**
 * @param srv_cfg *cfg
 * @return int
 */
int
tvpn_server_tcp_run(srv_cfg *cfg)
{
  int     ret;
  srv_tcp server;

  ret = 1;


ret:
  return ret;
}

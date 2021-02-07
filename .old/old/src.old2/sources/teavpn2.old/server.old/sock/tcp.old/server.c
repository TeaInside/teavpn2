
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <teavpn2/server/common.h>
#include <teavpn2/global/packet.h>

#include <teavpn2/server/sock/tcp.h>

server_tcp_state *g_state;

#define RACT(EXPR) (unlikely((state.stop) || (EXPR)))

#include "server/init.h"
#include "server/clean_up.h"

/**
 * @param server_cfg *config
 * @return int
 */
int
tvpn_server_tcp_run(server_cfg *config)
{
  int              ret    = 1;
  server_tcp_state state;

  if (!tvpn_server_init_first_state(&state, config)) {
    goto ret;
  }

  if (RACT(!tvpn_server_tcp_init_iface(&state))) {
    goto ret;
  }

  if (RACT(!tvpn_server_tcp_init_socket(&state))) {
    goto ret;
  }

  // ret = tvpn_server_tcp_event_loop(&state);

ret:

  tvpn_server_tcp_clean_up(&state);

  return ret;
}

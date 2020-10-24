
#include <teavpn2/server/common.h>
#include <teavpn2/global/packet.h>

#include <teavpn2/server/sock/tcp.h>
#include <teavpn2/server/sock/tcp_inline_functions.h>

#define RACT(EXPR) ((state.stop) || (EXPR))

server_tcp_state *g_state;

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
  int              ret = 1;
  const uint16_t   n   = config->sock.max_conn;
  server_tcp_state state;

  state.config   = config;
  state.stop     = false;
  state.net_fd   = -1;
  g_state        = &state;
  state.channels = (tcp_channel *)malloc(sizeof(tcp_channel) * n);

  tvpn_server_tcp_init_channels(state.channels, n);

  tvpn_general_init();

  if (RACT(!tvpn_server_tcp_init_iface(&state))) {
    goto ret;
  }

  if (RACT(!tvpn_server_tcp_init_socket(&state))) {
    goto ret;
  }

  ret = tvpn_server_tcp_event_loop(&state);

ret:
  tvpn_server_tcp_clean_up(&state);
  return ret;
}

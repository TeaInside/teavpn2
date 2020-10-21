
#include <teavpn2/server/common.h>
#include <teavpn2/global/packet.h>

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
  int               ret    = 1; /* Exit code. */
  server_tcp_state  state;

  g_state = &state;


  if (RACT(!tvpn_server_tcp_init_iface(&state))) {
    goto ret;
  }

  if (RACT(!tvpn_server_tcp_init_pipe(state.pipe_fd))) {
    goto ret;
  }

  if (RACT(!tvpn_server_tcp_init_socket(&state))) {
    goto ret;
  }

ret:
  tvpn_server_tcp_clean_up(&state);
  return ret;
}

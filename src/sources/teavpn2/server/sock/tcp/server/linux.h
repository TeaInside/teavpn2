
#if !defined(__linux__)
#  error "Compiler is not supported!"
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <teavpn2/server/sock/tcp.h>


#define PIPE_BUF (16)

server_tcp_state *g_state;

#include "linux/init.h"
#include "linux/iface.h"
#include "linux/accept.h"
#include "linux/clean_up.h"
#include "linux/client_event_loop.h"
#include "linux/master_event_loop.h"

/**
 * @param server_cfg *config
 * @return int
 */
int
tvpn_server_tcp_run(server_cfg *config)
{
  int               ret        = 1; /* Exit code. */
  const uint16_t    max_conn   = config->sock.max_conn;
  server_tcp_state  state;

  /* ================================================= */
  g_state        = &state;
  state.net_fd   = -1;
  state.stop     = false;
  state.config   = config;
  state.channels = (tcp_channel *)
                   malloc(sizeof(tcp_channel) * max_conn);
  tvpn_server_tcp_init_channels(state.channels, max_conn);
  /* ================================================= */

  if (!tvpn_server_tcp_init_iface(&state)) {
    goto ret;
  }

  if (!tvpn_server_tcp_init_pipe(state.pipe_fd)) {
    goto ret;
  }

  if (!tvpn_server_tcp_init_socket(&state)) {
    goto ret;
  }

  ret = tvpn_server_tcp_event_loop(&state);

ret:
  tvpn_server_tcp_clean_up(&state);
  return ret;
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H */

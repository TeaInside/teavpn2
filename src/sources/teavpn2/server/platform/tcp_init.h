
#ifndef SERVER__PLATFORM__TCP_INIT_H
#define SERVER__PLATFORM__TCP_INIT_H


inline static bool
tvpn_server_init_first_state(srv_tcp *state, srv_cfg *cfg);

inline static void
tvpn_server_tcp_init_channels(tcp_channel *channels, uint16_t n);

inline static void
tvpn_server_tcp_init_channel(tcp_channel *chan);

inline static bool
tvpn_server_tcp_init_iface(srv_tcp *state);

inline static bool
tvpn_server_tcp_init_socket(srv_tcp *state);


#if defined(__linux__)
#  include <poll.h>
#  include <fcntl.h>
#  include <errno.h>
#  include <signal.h>
#  include <unistd.h>
#  include <pthread.h>

#  include <arpa/inet.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/tcp.h>

// #  include "linux/init.h"
// #  include "linux/iface.h"
#else
#  error "Compiler is not supported!"
#endif


/**
 * @param srv_tcp *state
 * @param srv_cfg *cfg
 * @return bool
 */
inline static bool
tvpn_server_init_first_state(srv_tcp *state, srv_cfg *cfg)
{
  const uint16_t  n         = cfg->sock.max_conn;
  tcp_channel     *channels = NULL;

  channels = (tcp_channel *)malloc(sizeof(tcp_channel) * n);

  if (channels == NULL) {
    debug_log(0, "Cannot allocate memory!");
    return false;
  }

  tvpn_server_tcp_init_channels(channels, n);

  state->net_fd     = -1;
  state->stop       = false;
  state->channels   = channels;
  state->cfg        = cfg;
  state->pipe_fd[0] = -1;
  state->pipe_fd[1] = -1;

#if defined(__linux__)
  tvpn_server_tcp_init_pipe(state->pipe_fd);
#endif

  return true;
}


/**
 * @param tcp_channel *channels
 * @param uint16_t n
 * @return void
 */
inline static void
tvpn_server_tcp_init_channels(tcp_channel *channels, uint16_t n)
{
  for (uint16_t i = 0; i < n; i++) {
    tvpn_server_tcp_init_channel(&(channels[i]));
  }
}


/**
 * @param tcp_channel *chan
 * @return void
 */
inline static void
tvpn_server_tcp_init_channel(tcp_channel *chan)
{
  memset(chan, 0, sizeof(tcp_channel));
  chan->cli_fd = -1;
  chan->tun_fd = -1;
}


#endif /* #ifdef SERVER__PLATFORM__TCP_INIT_H

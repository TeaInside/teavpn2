
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__INIT_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__INIT_H


inline static bool
tvpn_server_init_first_state(server_tcp_state *state, server_cfg *config);

inline static void
tvpn_server_tcp_init_channels(tcp_channel *channels, uint16_t n);

inline static void
tvpn_server_tcp_init_channel(tcp_channel *chan);

inline static bool
tvpn_server_tcp_init_iface(server_tcp_state *state);

inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *state);


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

#  include "platform/linux/init.h"
#  include "platform/linux/iface.h"
#else
#  error "Compiler is not supported!"
#endif


/**
 * @param server_tcp_state *state
 * @param server_cfg       *config
 * @return bool
 */
inline static bool
tvpn_server_init_first_state(server_tcp_state *state, server_cfg *config)
{
  const uint16_t  n         = config->sock.max_conn;
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
  state->config     = config;
  state->pipe_fd[0] = -1;
  state->pipe_fd[1] = -1;

#if defined(__linux__)
  tvpn_server_tcp_init_pipe(state->pipe_fd);
  signal(SIGINT, tvpn_server_tcp_signal_handler);
  signal(SIGHUP, tvpn_server_tcp_signal_handler);
  signal(SIGTERM, tvpn_server_tcp_signal_handler);
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


#endif /* #ifdef TEAVPN2__SERVER__SOCK__TCP__SERVER__INIT_H */

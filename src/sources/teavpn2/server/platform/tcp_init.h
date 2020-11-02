
#ifndef SERVER__PLATFORM__TCP_INIT_H
#define SERVER__PLATFORM__TCP_INIT_H

inline static bool
tvpn_srv_tcp_init(srv_tcp *srv, srv_cfg *cfg);

inline static void
tvpn_srv_tcp_init_channels(tcp_channel *channels, uint16_t n);

inline static void
tvpn_srv_tcp_init_channel(tcp_channel *chan);

inline static bool
tvpn_srv_tcp_init_iface(srv_tcp *srv);

inline static bool
tvpn_srv_tcp_init_socket(srv_tcp *srv);


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

#  include "linux/tcp_init.h"
#else
#  error "Compiler is not supported!"
#endif

#define ECT(EXPR) (unlikely((srv->stop || (EXPR))))

/**
 * @param srv_tcp *srv
 * @param srv_cfg *cfg
 * @return bool
 */
inline static bool
tvpn_srv_tcp_init(srv_tcp *srv, srv_cfg *cfg)
{
  srv->net_fd     = -1;
#if defined(__linux__)
  srv->pipe_fd[0] = -1;
  srv->pipe_fd[1] = -1;
#endif
  srv->fci        = -1;
  srv->cfg        = cfg;
  srv->channels   = NULL;
  srv->stop       = false;

  {
    const uint16_t  n         = cfg->sock.max_conn;
    tcp_channel     *channels;

    channels = (tcp_channel *)malloc(sizeof(tcp_channel) * n);
    if (channels == NULL) {
      debug_log(0, "Cannot allocate memory!");
      return false;
    }
    tvpn_srv_tcp_init_channels(channels, n);
    srv->channels = channels;
  }

  if (!tvpn_srv_tcp_init_iface(srv)) {
    return false;
  }

#if defined(__linux__)
  if (ECT(!tvpn_srv_tcp_init_pipe(srv->pipe_fd))) {
    return false;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, tvpn_srv_tcp_signal_handler);
  signal(SIGHUP, tvpn_srv_tcp_signal_handler);
  signal(SIGTERM, tvpn_srv_tcp_signal_handler);
#endif

  if (ECT(!tvpn_srv_tcp_init_socket(srv))) {
    return false;
  }

  return true;
}


/**
 * @param tcp_channel *channels
 * @param uint16_t n
 * @return void
 */
inline static void
tvpn_srv_tcp_init_channels(tcp_channel *channels, uint16_t n)
{
  for (uint16_t i = 0; i < n; i++) {
    tvpn_srv_tcp_init_channel(&(channels[i]));
  }
}


/**
 * @param tcp_channel *chan
 * @return void
 */
inline static void
tvpn_srv_tcp_init_channel(tcp_channel *chan)
{
  memset(chan, 0, sizeof(tcp_channel));
  chan->cli_fd = -1;
  chan->tun_fd = -1;
}


#endif /* #ifdef SERVER__PLATFORM__TCP_INIT_H */

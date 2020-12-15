
#ifndef SERVER__PLATFORM__LINUX__CLEAN_UP_H
#define SERVER__PLATFORM__LINUX__CLEAN_UP_H


inline static void
tvpn_srv_tcp_close_net_fd(int net_fd);

inline static void
tvpn_srv_tcp_close_pipe_fd(int pipe_fd[2]);


/**
 * @param srv_tcp *srv
 * @return void
 */
inline static void
tvpn_srv_tcp_clean_up(srv_tcp *srv)
{
  const uint16_t n         = srv->cfg->sock.max_conn;
  tcp_channel    *channels = srv->channels;


  if (channels != NULL) {
    for (uint16_t i = 0; i < n; ++i) {
      int the_fd = channels[i].tun_fd;

      if (channels[i].is_used) {
        debug_log(0, "Closing connected client(s)...");
        pthread_kill(channels[i].thread, SIGTERM);
        pthread_mutex_lock(&(channels[i].ht_mutex));
      }

      if (the_fd != -1) {
        debug_log(0, "Closing tun_fd -> (%d)", the_fd);
        close(the_fd);
      }

      if (channels[i].is_used) {
        pthread_mutex_unlock(&(channels[i].ht_mutex));
      }
    }

    free(channels);
  }

  tvpn_srv_tcp_close_pipe_fd(srv->pipe_fd);
  tvpn_srv_tcp_close_net_fd(srv->net_fd);
}


/**
 * @param int net_fd
 * @return void
 */
inline static void
tvpn_srv_tcp_close_net_fd(int net_fd)
{
  /* Close TCP socket. */
  if (net_fd != -1) {
    debug_log(0, "Closing net_fd -> (%d)...", net_fd);
    close(net_fd);
  }
}


/**
 * @param int pipe_fd[2]
 * @return void
 */
inline static void
tvpn_srv_tcp_close_pipe_fd(int pipe_fd[2])
{
  if (pipe_fd[0] != -1) {
    debug_log(0, "Closing pipe_fd[0] -> (%d)...", pipe_fd[0]);
    close(pipe_fd[0]);
  }

  if (pipe_fd[1] != -1) {
    debug_log(0, "Closing pipe_fd[1] -> (%d)...", pipe_fd[1]);
    close(pipe_fd[1]);
  }
}

#endif /* #ifndef SERVER__PLATFORM__LINUX__CLEAN_UP_H */

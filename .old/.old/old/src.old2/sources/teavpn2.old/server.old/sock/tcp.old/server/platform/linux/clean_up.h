
#ifndef __PLATFORM__LINUX__CLEAN_UP_H
#define __PLATFORM__LINUX__CLEAN_UP_H

#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

/**
 * @param server_tcp_state *state
 * @return void
 */
inline static void
tvpn_server_tcp_clean_up(server_tcp_state *state)
{
  const uint16_t n         = state->config->sock.max_conn;
  int            net_fd    = state->net_fd;
  tcp_channel    *channels = state->channels;

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

  /* Close pipe_fd */
  if (pipe_fd[0] != -1) {
    debug_log(0, "Closing pipe_fd[0] -> (%d)...", pipe_fd[0]);
    close(pipe_fd[0]);   
  }
  if (pipe_fd[1] != -1) {
    debug_log(0, "Closing pipe_fd[1] -> (%d)...", pipe_fd[1]);
    close(pipe_fd[0]);   
  }

  /* Close TCP socket. */
  if (net_fd != -1) {
    debug_log(0, "Closing net_fd -> (%d)...", net_fd);
    close(net_fd);
  }
}

#endif /* #ifndef __PLATFORM__LINUX__CLEAN_UP_H */

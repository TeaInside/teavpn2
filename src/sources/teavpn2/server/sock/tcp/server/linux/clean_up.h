
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLEAN_UP_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLEAN_UP_H


/**
 * @param server_tcp_state *__restrict__ state
 * @return void
 */
inline static void
tvpn_server_tcp_clean_up_tun_fd(server_tcp_state *__restrict__ state)
{
  /* Close tun fd(s). */
  register uint16_t    max_conn  = state->config->sock.max_conn;
  register tcp_channel *channels = state->channels;

  for (uint16_t i = 0; i < max_conn; ++i) {
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


/**
 * @param server_tcp_state *__restrict__ state
 * @return void
 */
inline static void
tvpn_server_tcp_close_socket(server_tcp_state *__restrict__ state)
{
  register int net_fd = state->net_fd;

  /* Close TCP socket. */
  if (net_fd != -1) {
    debug_log(0, "Closing net_fd -> (%d)...", net_fd);
    close(net_fd);
  }
}


/**
 * @param server_tcp_state *__restrict__ state
 * @return void
 */
inline static void
tvpn_server_tcp_clean_up(server_tcp_state *__restrict__ state)
{
  tvpn_server_tcp_clean_up_tun_fd(state);
  tvpn_server_tcp_close_socket(state);
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLEAN_UP_H */

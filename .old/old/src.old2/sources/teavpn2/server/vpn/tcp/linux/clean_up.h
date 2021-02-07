
#ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#  error This file must be included from \
         src/sources/teavpn2/server/teavpn2/tcp/linux.h
#endif

#ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__CLEAN_UP_H
#define SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__CLEAN_UP_H

#define CLOSE_FD(FD)                                \
do {                                                \
  if (close((FD)) == -1) {                          \
    err_printf("Error close: %s", strerror(errno)); \
  }                                                 \
} while (0)

/**
 * @param tcp_state *state
 * @return void
 */
inline static void
tsrv_clean_up_tcp(tcp_state *state)
{
  srv_cfg        *cfg     = state->cfg;
  tcp_channel    *chan    = state->chan;
  const uint16_t max_conn = cfg->sock.max_conn;

  if (state->net_fd != -1) {
    log_printf(1, "Closing TCP file descriptor (%d)...", state->net_fd);
    CLOSE_FD(state->net_fd);
  }

  if (state->pipe_fd[0] != -1) {
    log_printf(1, "Closing pipe_fd[0] (%d)...", state->pipe_fd[0]);
    CLOSE_FD(state->pipe_fd[0]);
  }

  if (state->pipe_fd[1] != -1) {
    log_printf(1, "Closing pipe_fd[1] (%d)...", state->pipe_fd[1]);
    CLOSE_FD(state->pipe_fd[1]);
  }


  for (uint16_t i = 0; i < max_conn; i++) {
    if (chan[i].is_used) {
      /* Wait for the thread to complete. */
      pthread_mutex_lock(&(chan[i].ht_mutex));
      pthread_mutex_unlock(&(chan[i].ht_mutex));
    }

    if (chan[i].cli_fd != -1) {
      log_printf(1, "Closing chan[%d].cli_fd (%d)...", i, chan[i].cli_fd);
      CLOSE_FD(chan[i].cli_fd);
    }

    if (chan[i].tun_fd != -1) {
      log_printf(1, "Closing chan[%d].tun_fd (%d)...", i, chan[i].tun_fd);
      CLOSE_FD(chan[i].tun_fd);
    }
  }


  free(chan);
}

#endif /* #ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__CLEAN_UP_H */

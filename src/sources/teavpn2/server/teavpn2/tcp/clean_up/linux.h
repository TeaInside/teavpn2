
#ifndef TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#  error This file must be included from \
         src/sources/teavpn2/server/teavpn2/tcp/linux.h
#endif

#ifndef TEAVPN2__SERVER__TEAVPN2__TCP__CLEAN_UP__LINUX_H
#define TEAVPN2__SERVER__TEAVPN2__TCP__CLEAN_UP__LINUX_H

#define CLOSE_FD(FD)                                \
do {                                                \
  if (close(FD) == -1) {                            \
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
}

#endif /* #ifndef TEAVPN2__SERVER__TEAVPN2__TCP__CLEAN_UP__LINUX_H */

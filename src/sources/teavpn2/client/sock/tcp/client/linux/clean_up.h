
#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX_H
#  error This file must only be included from   \
         teavpn2/client/sock/tcp/client/linux.h
#endif

#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__CLEAN_UP_H
#define TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__CLEAN_UP_H

/**
 * @param int tun_fd
 * @return void
 */
inline static void
tvpn_client_tcp_close_tun_fd(int tun_fd)
{
  if (tun_fd != -1) {
    debug_log(0, "Closing tun_fd -> (%d)", tun_fd);
    close(tun_fd);
  }
}


/**
 * @param int net_fd
 * @return void
 */
inline static void
tvpn_client_tcp_close_net_fd(int net_fd)
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
tvpn_client_tcp_close_pipe_fd(int pipe_fd[2])
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


/**
 * @param client_tcp_state *__restrict__ state
 * @return void
 */
inline static void
tvpn_client_tcp_clean_up(client_tcp_state *__restrict__ state)
{
  tvpn_client_tcp_close_tun_fd(state->tun_fd);
  tvpn_client_tcp_close_pipe_fd(state->pipe_fd);
  tvpn_client_tcp_close_net_fd(state->net_fd);
}


#endif /* #ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__CLEAN_UP_H */

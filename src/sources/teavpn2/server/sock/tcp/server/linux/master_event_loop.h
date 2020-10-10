
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__MASTER_EVENT_LOOP_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__MASTER_EVENT_LOOP_H


/**
 * @param server_tcp_state *__restrict__ state
 * @return int
 */
inline static int
tvpn_server_tcp_event_loop(server_tcp_state *__restrict__ state)
{
  int            ret = 1;
  nfds_t         nfds;
  struct pollfd  fds[2];
  int            timeout;
  int            *pipe_fd = state->pipe_fd;

  memset(fds, 0, sizeof(fds));

  /* ======================================================= */
  /* Add TCP socket fd to fds. */
  fds[0].fd     = state->net_fd;
  fds[0].events = POLLIN;

  /* Add pipe fd to fds.       */
  fds[1].fd     = pipe_fd[0];
  fds[1].events = POLLIN;

  nfds         = 2;            /* Number of fds.           */
  timeout      = 3000;         /* Poll inactivity timeout. */
  /* ======================================================= */


  /* Poll event loop. */
  while (true) {
    int rv;

    rv = poll(fds, nfds, timeout);

    /* Poll reached timeout/interrupted. */
    if (likely(rv == 0)) {
      goto end_loop;
    }

    /* Accept new client. */
    if (unlikely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_accept(state);
    }

    /* Pipe interrupt. */
    if (unlikely(fds[1].revents == POLLIN)) {
      char buf[PIPE_BUF];
      if (read(pipe_fd[0], buf, PIPE_BUF) < 0) {
        debug_log(0, "Error reading from pipe_fd[0]: %s", 
          strerror(errno));
      }
    }

    end_loop:
    if (state->stop) {
      ret = 0;
      break;
    }
  }
  /* End of poll event loop. */

  return ret;
}

#endif /* #ifndef
TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__MASTER_EVENT_LOOP_H */

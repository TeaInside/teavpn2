
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_CLIENT_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_CLIENT_H


/**
 * @param void *_chan
 * @return void *
 */
inline static void *
tvpn_server_tcp_thread_worker(void *_chan)
{
  tcp_channel *chan = (tcp_channel *)_chan;


  /* This mutex will make the thread killed gracefully. */
  pthread_mutex_lock(&(chan->ht_mutex));
  tvpn_server_tcp_client_event_loop(chan);
  pthread_mutex_unlock(&(chan->ht_mutex));

  return NULL;
}

/**
 * @param void *chan
 * @return void
 */
inline static void
tvpn_server_tcp_client_event_loop(tcp_channel *chan)
{
  struct pollfd     fds[1];
  uint32_t          timeout_c = 0;
  nfds_t            nfds      = 1;       /* Number of fds.           */
  int               timeout   = 3000;    /* Poll inactivity timeout. */
  server_tcp_state  *state    = g_state;

  fds[0].fd     = chan->cli_fd;
  fds[0].events = POLLIN;

  while (true) {
    int rv;

    rv = poll(fds, nfds, timeout);

    /* Poll reached timeout or interrupted. */
    if (unlikely(rv == 0)) {

      timeout_c++;

      /*
       * If the client has not been authorized in
       * the given of time, it will be disconnected.
       */
      if ((timeout_c >= 3) && (!chan->is_authorized)) {
        break;
      }

      /* Client is authorized, so we keep the connection alive */
      goto end_loop;
    }

    if (likely(fds[0].revents == POLLIN)) {

    }

  end_loop:
    if (unlikely(state->stop | chan->stop)) {
      /* Stop state detected, break the event loop. */
      break;
    }
  }


}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_CLIENT_H */

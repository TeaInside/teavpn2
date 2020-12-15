
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_MASTER_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_MASTER_H


/**
 * @param server_tcp_state *state
 * @return int
 */
inline static int
tvpn_server_tcp_event_loop(server_tcp_state *state)
{
  int            ret      = 1;
  int            *pipe_fd = state->pipe_fd;
  uint16_t       max_conn = state->config->sock.max_conn;
  int            timeout;
  nfds_t         nfds;
  struct pollfd  fds[2 + max_conn];

  for (int i = 0; i < (2 + max_conn); i++) {
    memset(&(fds[i]), 0, sizeof(struct pollfd));
  }

  /* Add TCP socket fd to fds.       */
  fds[0].fd     = state->net_fd;
  fds[0].events = POLLIN;

  /* Add pipe fd for reading to fds. */
  fds[1].fd     = pipe_fd[0];
  fds[1].events = POLLIN;

  nfds          = 2;            /* Number of fds.           */
  timeout       = 3000;         /* Poll inactivity timeout. */

  while (true) {
    int rv;
    rv = poll(fds, nfds, timeout);

    /* Poll reached timeout or interrupted. */
    if (unlikely(rv == 0)) {
      goto end_loop;
    }

    /* Accept new client. */
    if (unlikely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_accept(state, fds, &nfds);
    }





  end_loop:
    if (unlikely(state->stop)) {
      ret = 0;
      break;
    }
  }

  return ret;
}


/**
 * @param server_tcp_state *state
 * @param struct pollfd    *fds
 * @param nfds_t           *nfds
 * @return int
 */
inline static void
tvpn_server_tcp_accept(server_tcp_state *state, struct pollfd *fds,
                       nfds_t *nfds)
{
  int                ret;
  int                net_fd  = state->net_fd;
  socklen_t          rlen    = sizeof(struct sockaddr_in);
  struct sockaddr_in claddr;
  unsigned long      s_addr;
  char               _remote_addr[16]; /* Readable IPv4. */
  const char         *remote_addr = NULL;
  uint16_t           remote_port  = 0;

  ret = accept(net_fd, (struct sockaddr *)&claddr, &rlen);

  if (ret < 0) {

    if (errno == EWOULDBLOCK) {
      /* Operation would block (Non-blocking socket). */
      return;
    }
    debug_log(0, "Error accept(): %s", strerror(errno));
    return;
  }

  s_addr      = claddr.sin_addr.s_addr;
  remote_addr = inet_ntop(AF_INET, &s_addr, _remote_addr,
                          sizeof(remote_addr));

  if (remote_addr == NULL) {
    debug_log(0, "Error inet_ntop(): %s", strerror(errno));
    goto close;
  }

  remote_port = ntohs(claddr.sin_port);

  {
    int         ret;
    uint16_t    n         = state->config->sock.max_conn;
    tcp_channel *channels = state->channels;
    tcp_channel *chan     = tvpn_server_tcp_get_channel(channels, n);

    if (!chan) {
      debug_log(2, "Channel is full, cannot accept more connection");
      goto close;
    }

    if ((ret = pthread_mutex_init(&(chan->ht_mutex), NULL)) != 0) {
      debug_log(0, "Error pthread_mutex_init(): %s", strerror(ret));
      goto close;
    }

    pthread_mutex_lock(&(chan->ht_mutex));

    /* Open a channel for new client. */
    if (!tvpn_server_tcp_create_channel(chan, ret, remote_addr,
                                        remote_port,
                                        &claddr)) {
      goto close;
    }

    fds[*nfds - 1].fd     = chan->tun_fd;
    fds[*nfds - 1].events = POLLIN;
    (*nfds)++;

    pthread_mutex_unlock(&(chan->ht_mutex));
  }

  return;
close:
  debug_log(0, "Closing connection from %s:%d...", remote_addr,
            remote_port);
  close(ret);
}


/**
 * @param tcp_channel *channels
 * @param uint16_t    n
 * @return tcp_channel *
 */
inline static tcp_channel *
tvpn_server_tcp_get_channel(tcp_channel *channels, uint16_t n)
{
  for (uint16_t i = 0; i < n; ++i) {
    __sync_synchronize();
    if (!channels[i].is_used) {
      return &(channels[i]);
    }
    __sync_synchronize();
  }

  return NULL;
}


/**
 * @param tcp_channel        *chan
 * @param int                fd
 * @param const char         *remote_addr
 * @param uint16_t           remote_port
 * @param struct sockaddr_in *claddr
 * @return bool
 */
inline static bool
tvpn_server_tcp_create_channel(tcp_channel *chan,
                               int fd,
                               const char *remote_addr,
                               uint16_t remote_port,
                               struct sockaddr_in *claddr)
{
  /* Enable tun queue. */
  if (tun_set_queue(chan->tun_fd, true) < 0) {
    debug_log(0, "Error tun_set_queue(): %s", strerror(errno));
    return false;
  }

  strncpy(chan->r_ip_src, remote_addr, sizeof(chan->r_ip_src));
  chan->r_port_src      = remote_port;
  chan->stop            = false;
  chan->is_used         = true;
  chan->is_connected    = true;
  chan->is_authorized   = false;
  chan->cli_fd          = fd;
  chan->p_ipv4          = 0;
  chan->p_ipv4_netmask  = 0;
  chan->username        = NULL;
  chan->addr            = *claddr;

  memset(chan->recv_buff, 0, sizeof(chan->recv_buff));
  chan->recv_size       = 0;
  chan->recv_count      = 0;
  chan->recv_err_c      = 0;

  memset(chan->send_buff, 0, sizeof(chan->send_buff));
  chan->send_size       = 0;
  chan->send_count      = 0;
  chan->send_err_c      = 0;


  debug_log(2, "New connection from %s:%d", HP_CC(chan));

  pthread_create(&(chan->thread), NULL,
                 tvpn_server_tcp_thread_worker,
                 (void *)chan);
  pthread_detach(chan->thread);

  return true;
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__EVL_MASTER_H */

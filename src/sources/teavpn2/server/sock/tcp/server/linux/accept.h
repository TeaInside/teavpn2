
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H

inline static bool
tvpn_server_tcp_insert_channel(int fd, tcp_channel *__restrict__ chan,
                               struct sockaddr_in *__restrict__ claddr);


inline static void *
tvpn_server_tcp_thread_worker(void *__restrict__ _chan);


/**
 * @param tcp_channel  *__restrict__ channels
 * @return int32_t
 */
inline static int32_t
tvpn_server_tcp_get_chan(server_tcp_state *__restrict__ state)
{
  register tcp_channel  *channels = state->channels;
  register uint16_t     max_conn  = state->config->sock.max_conn;

  for (uint16_t i = 0; i < max_conn; i++) {
    if (!channels[i].is_used) {
      return (int32_t)i;
    }
  }

  return -1;
}


/**
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static void
tvpn_server_tcp_accept(server_tcp_state *__restrict__ state)
{
  register int          ret;
  register int          net_fd    = state->net_fd;
  register int32_t      idx       = -1;
  register tcp_channel  *channels = state->channels;
  register tcp_channel  *chan;

  struct sockaddr_in    claddr;
  socklen_t             rlen   = sizeof(struct sockaddr_in);

  ret = accept(net_fd, (struct sockaddr *)&claddr, &rlen);

  if (ret < 0) {

    if (errno == EWOULDBLOCK) {
      return;
    }

    debug_log(0, "Error accept(): %s", strerror(errno));
    return;
  }


  {
    char          remote_addr[16] = {0};
    uint16_t      remote_port     = 0;
    unsigned long s_addr;
    const char    *iret;

    s_addr = claddr.sin_addr.s_addr;
    iret   = inet_ntop(AF_INET, &s_addr, remote_addr, sizeof(remote_addr));

    if (iret == NULL) {
      debug_log(0, "Error inet_ntop(): %s", strerror(errno));
      goto close;
    }

    remote_port = ntohs(claddr.sin_port);


    /* Prepare the channel for new client. */
    idx = tvpn_server_tcp_get_chan(state);

    if (idx == -1) {
      debug_log(2, "Connection channels is full, cannot accept more client.");
      goto close;
    }


    chan = &(channels[idx]);

    {
      /* Init mutex. */
      int ret;
      if ((ret = pthread_mutex_init(&(chan->ht_mutex), NULL)) != 0) {
        debug_log(0, "Error pthread_mutex_init(): %s", strerror(ret));
        goto close;
      }
    }

    if (!tvpn_server_tcp_insert_channel(ret, chan, &claddr)) {
      goto close;
    }

    /* Copy remote addr and remote port to channel. */
    strncpy(chan->r_ip_src, remote_addr, sizeof(chan->r_ip_src));
    chan->r_port_src = remote_port;

    debug_log(2, "New connection from %s:%d", HP_CC(chan));

    pthread_create(&(chan->thread), NULL, tvpn_server_tcp_thread_worker,
                   (void *)chan);

    pthread_detach(chan->thread);

    return;

  close:
    debug_log(0, "Closing connection from %s:%d...", remote_addr,
              remote_port);
    close(ret);
  }
}


/**
 * @param int                              fd
 * @param tcp_channel *__restrict__        chan
 * @param struct sockaddr_in *__restrict__ claddr
 * @return bool
 */
inline static bool
tvpn_server_tcp_insert_channel(int fd, tcp_channel *__restrict__ chan,
                               struct sockaddr_in *__restrict__ claddr)
{

  if (tun_set_queue(chan->tun_fd, true) < 0) {
    debug_log(0, "tun_set_queue(): %s", strerror(errno));
    return false;
  }

  chan->is_used        = true;
  chan->is_connected   = true;
  chan->is_authorized  = false;
  chan->cli_fd         = fd;
  chan->p_ipv4         = 0;
  chan->p_ipv4_netmask = 0;
  chan->username       = NULL;
  chan->addr           = *claddr;

  memset(chan->recv_buff, 0, sizeof(chan->recv_buff));
  chan->recv_size      = 0;
  chan->recv_count     = 0;

  memset(chan->send_buff, 0, sizeof(chan->send_buff));
  chan->send_size      = 0;
  chan->send_count     = 0;

  return true;
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H */


#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_close_client(tcp_channel *__restrict__ chan)
{
  int tun_fd = chan->tun_fd;
  int cli_fd = chan->cli_fd;


  debug_log(2, "[%s:%d] Detaching tun queue -> (%d)...",
            HP_CC(chan), tun_fd);

  tun_set_queue(tun_fd, false);

  debug_log(0, "Closing connection from %s:%d (%d)...",
            HP_CC(chan), cli_fd);

  close(cli_fd);

  chan->stop          = true;
  chan->is_connected  = false;
  chan->is_used       = false;
  chan->is_authorized = false;
  chan->username      = NULL;
}


/**
 * @param tcp_channel       *__restrict__ chan
 * @param register uint16_t rdata_size
 * @param register uint16_t pkt_len
 * @return void
 */
inline static void
tvpn_server_tcp_event_auth(tcp_channel *__restrict__ chan,
                           register uint16_t rdata_size,
                           register uint16_t pkt_len)
{

  if (rdata_size < pkt_len) {
    /* Data has not been received completely. */
    return;
  }


  {
    cl_pkt       *cli_pkt  = (cl_pkt *)chan->recv_buff;
    cl_pkt_auth  *auth_pkt = (cl_pkt_auth *)cli_pkt->data;
    char         *username = &(auth_pkt->data[0]);
    char         *password = &(auth_pkt->data[auth_pkt->username_len + 1]);

    /* For string safety. */
    username[auth_pkt->username_len] = '\0';
    password[auth_pkt->password_len] = '\0';

    printf("Username: \"%s\"\n", username);
    printf("Password: \"%s\"\n", password);

    chan->recv_size = 0;
  }
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_client_handle_cli(tcp_channel *__restrict__ chan)
{
  register ssize_t  ret;        /* recv() return value.          */
  register char     *buff;      /* Buffer pointer.               */
  register size_t   recv_size;  /* Number of bytes in recv_buff. */
  register int      cli_fd;     /* FD to read from client.       */

  cli_fd    = chan->cli_fd;
  recv_size = chan->recv_size;
  buff      = &(chan->recv_buff[recv_size]);

  ret = recv(cli_fd, buff, RECVBZ - recv_size, 0);

  if (likely(ret < 0)) {

    if (errno == EWOULDBLOCK) {
      return;
    }

    debug_log(0, "[%s:%d] Error recv(): %s", HP_CC(chan),
              strerror(errno));

    chan->recv_err_c++;
    if (chan->recv_err_c >= MAX_RECV_ERR_CC) {
      chan->stop = true;
      debug_log(
        0, "[%s:%d] Reached the max number of errors: %d",
        HP_CC(chan),
        MAX_RECV_ERR_CC
      );
    }

    return;

  } else
  if (unlikely(ret == 0)) {
    /* Client has been disconnected. */
    chan->stop = true;
    debug_log(0, "[%s:%d] Disconnect state detected.", HP_CC(chan));
    return;
  }

  debug_log(5, "[%s:%d] recv() %d bytes", HP_CC(chan), ret);

  chan->recv_size += (size_t)ret;

  if (chan->recv_size >= CL_IDENT_SZ) {
    register cl_pkt   *cli_pkt;
    register uint16_t pkt_len;
    register uint16_t rdata_size; /* Number of bytes in data (cli_pkt). */

    rdata_size = chan->recv_size - CL_IDENT_SZ;
    cli_pkt    = (cl_pkt *)chan->recv_buff;
    pkt_len    = ntohs(cli_pkt->len);

    switch (cli_pkt->type) {
      case CL_PKT_PING:
        chan->recv_size = 0;
        return;

      case CL_PKT_AUTH:
        tvpn_server_tcp_event_auth(chan, rdata_size, pkt_len);
        break;

      case CL_PKT_DATA:
        break;

      case CL_PKT_DISCONNECT:
        chan->recv_size = 0;
        chan->stop      = true;
        return;

      default:
        chan->recv_size = 0;
        debug_log(3, "[%s:%d] Got invalid packet type: %d",
                  HP_CC(chan), cli_pkt->type);
        return;
    }

    /* Next packet is read at the moment. */
    if (rdata_size > pkt_len) {
      buff            = &(chan->recv_buff[CL_IDENT_SZ + pkt_len]);
      chan->recv_size = rdata_size - pkt_len;
      memmove(chan->recv_buff, buff, chan->recv_size);
      debug_log(4, "[%s:%d] Next packet is read at the moment: %d bytes",
                HP_CC(chan), chan->recv_size);
    }
  }
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_client_handle_tun(tcp_channel *__restrict__ chan)
{
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_client_event_loop(tcp_channel *__restrict__ chan)
{
  struct pollfd     fds[2];
  uint32_t          timeout_c = 0;
  nfds_t            nfds      = 2;       /* Number of fds.           */
  int               timeout   = 3000;    /* Poll inactivity timeout. */
  server_tcp_state  *state    = g_state;

  fds[0].fd     = chan->cli_fd;
  fds[0].events = POLLIN;

  fds[1].fd     = chan->tun_fd;
  fds[1].events = POLLIN;

  while (true) {
    int rv;

    rv = poll(fds, nfds, timeout);

    /* Poll reached timeout/interrupted. */
    if (unlikely(rv == 0)) {
      timeout_c++;

      /*
       * Connected client must be authorized in the
       * given of time or it will be disconnected.
       */
      if ((timeout_c >= 3) && (!chan->is_authorized)) {
        break;
      }

      goto end_loop;
    }

    if (likely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_client_handle_cli(chan);
    }

    if (likely(fds[1].revents == POLLIN)) {
      tvpn_server_tcp_client_handle_tun(chan);
    }

  end_loop:
    if (state->stop | chan->stop) {
      break;
    }
  }
}


/**
 * @param void *__restrict__ chan
 * @return void
 */
inline static void *
tvpn_server_tcp_thread_worker(void *__restrict__ _chan)
{
  register tcp_channel *chan = (tcp_channel *)_chan;


  pthread_mutex_lock(&(chan->ht_mutex));


  debug_log(0, "[%s:%d] Spawning a thread to handle new connection...",
            HP_CC(chan));

  tvpn_server_tcp_client_event_loop(chan);

  tvpn_server_tcp_close_client(chan);

  pthread_mutex_unlock(&(chan->ht_mutex));

  return NULL;
}

#endif /* #ifndef
TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H */

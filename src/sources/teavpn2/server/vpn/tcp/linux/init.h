
#ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#  error This file must be included from \
         src/sources/teavpn2/server/teavpn2/tcp/linux.h
#endif

#ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__INIT_H
#define SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__INIT_H

/**
 * @param tcp_state *state
 * @return bool
 */
inline static bool
tsrv_init_sock_tcp(tcp_state *state)
{
  int                 retval;
  int                 net_fd;
  struct sockaddr_in  srvaddr;
  srv_sock_cfg        *sock_cfg  = &(state->cfg->sock);


  const char          *bind_addr = sock_cfg->bind_addr;
  uint16_t            bind_port  = sock_cfg->bind_port;
  int                 backlog    = sock_cfg->backlog;


  if (unlikely(bind_addr == NULL)) {
    bind_addr = "0.0.0.0";
  }


  log_printf(5, "Creating TCP socket...");

  /* Create TCP socket. */
  net_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

  if (unlikely(net_fd < 0)) {
    err_printf("Error creating TCP socket: %s", strerror(errno));
    return -1;
  }

  log_printf(5, "TCP socket created successfully with fd %d", net_fd);


  memset(&srvaddr, 0, sizeof(struct sockaddr_in));
  srvaddr.sin_family      = AF_INET;
  srvaddr.sin_port        = htons(bind_port);
  srvaddr.sin_addr.s_addr = inet_addr(bind_addr);


  /* Bind to the address and port. */
  retval = bind(net_fd, (struct sockaddr *)&srvaddr,
                sizeof(struct sockaddr_in));

  if (unlikely(retval < 0)) {
    err_printf("Error bind: %s", strerror(errno));
    goto err_close;
  }


  retval = listen(net_fd, backlog);

  if (unlikely(retval < 0)) {
    err_printf("Error listen: %s", strerror(errno));
    goto err_close;
  }


  log_printf(0, "Listening on %s:%d...", bind_addr, bind_port);


  state->net_fd = net_fd;

  return true;

err_close:
  log_printf(5, "Closing TCP file descriptor (%d)...", net_fd);
  close(net_fd);
  return false;
}


/**
 * @param tcp_state *state
 * @return bool
 */
inline static bool
tsrv_init_pipe_tcp(tcp_state *state)
{
  if (pipe(state->pipe_fd) == -1) {
    err_printf("Error pipe: %s", strerror(errno));
    return false;
  }
  return true;
}


/**
 * @param tcp_channel     *chan
 * @param const uint16_t  n
 * @return void
 */
inline static void
tsrv_init_channel_tcp(tcp_channel *chan, const uint16_t n)
{
  for (uint16_t i = 0; i < n; i++) {
    chan[i].stop           = false;
    chan[i].is_used        = false;
    chan[i].is_connected   = false;
    chan[i].is_authorized  = false;
    chan[i].tun_fd         = -1;
    chan[i].cli_fd         = -1;
    chan[i].p_ipv4         = 0;
    chan[i].p_ipv4_netmask = 0;

    memset(chan[i].username, 0, sizeof(chan[i].username));
    memset(chan[i].r_ip_src, 0, sizeof(chan[i].username));
    chan[i].r_port_src     = 0;

    memset(&(chan[i].addr), 0, sizeof(struct sockaddr_in));

    memset(chan[i].recv_buff, 0, sizeof(chan[i].recv_buff));
    chan[i].recv_size   = 0;
    chan[i].recv_c      = 0;
    chan[i].recv_err_c  = 0;

    memset(chan[i].send_buff, 0, sizeof(chan[i].send_buff));
    chan[i].send_size   = 0;
    chan[i].send_c      = 0;
    chan[i].send_err_c  = 0;
  }
}

#endif /* #ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX__INIT_H */

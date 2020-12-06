
#ifndef TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#  error This file must be included from \
         src/sources/teavpn2/server/teavpn2/tcp/linux.h
#endif

#ifndef TEAVPN2__SERVER__TEAVPN2__TCP__SOCK__LINUX_H
#define TEAVPN2__SERVER__TEAVPN2__TCP__SOCK__LINUX_H

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
tsrv_init_pipe(tcp_state *state)
{
  if (pipe(state->pipe_fd) == -1) {
    err_printf("Error pipe: %s", strerror(errno));
    return false;
  }
  return true;
}

#endif /* #ifndef TEAVPN2__SERVER__TEAVPN2__TCP__SOCK__LINUX_H */


#ifndef SERVER__PLATFORM__LINUX__INIT_H
#define SERVER__PLATFORM__LINUX__INIT_H


inline static bool
tvpn_srv_tcp_socket_setup(int fd);


/**
 * @param int signal
 * @return void
 */
inline static void
tvpn_srv_tcp_signal_handler(int signal)
{
  (void)signal;
  g_srv->stop = true;
  __sync_synchronize();
  puts("");
}


/**
 * @param int pipe_fd[2]
 * @return bool
 */
inline static bool
tvpn_srv_tcp_init_pipe(int pipe_fd[2])
{
  if (pipe(pipe_fd) < 0) {
    debug_log(0, "Error pipe(): %s", strerror(errno));
    return false;
  }

  return true;
}


/**
 * @param srv_tcp *srv
 * @return bool
 */
inline static bool
tvpn_srv_tcp_init_socket(srv_tcp *srv)
{
  int                fd;
  int                rv;
  struct sockaddr_in srv_addr;
  srv_sock_cfg       *sock_cfg    = &(srv->cfg->sock);

  /*
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(2, "Creating TCP socket...");
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    debug_log(0, "Error socket(): %s", strerror(errno));
    return false;
  }
  debug_log(5, "TCP socket created successfully!");


  /*
   * Setup TCP socket.
   */
  debug_log(2, "Setting up socket file descriptor...");
  if (!tvpn_srv_tcp_socket_setup(fd)) {
    return false;
  }
  debug_log(5, "Socket file descriptor set up successfully!");

  /*
   * Prepare server bind address data.
   */
  memset(&srv_addr, 0, sizeof(struct sockaddr_in));
  srv_addr.sin_family      = AF_INET;
  srv_addr.sin_port        = htons(sock_cfg->bind_port);
  srv_addr.sin_addr.s_addr = inet_addr(sock_cfg->bind_addr);

  /*
   * Bind socket to address.
   */
  rv = bind(fd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
  if (rv < 0) {
    debug_log(0, "Error bind(): %s", strerror(errno));
    goto err;
  }

  /*
   * Listen socket.
   */
  if (listen(fd, sock_cfg->backlog) < 0) {
    debug_log(0, "Error listen(): %s", strerror(errno));
    goto err;
  }

  debug_log(0, "Listening on %s:%d...",
            sock_cfg->bind_addr,
            sock_cfg->bind_port);


  srv->net_fd = fd;

  return true;
err:
  if (fd != -1) {
    debug_log(0, "Closing socket descriptor...");
    close(fd);
  }
  return false;
}


/**
 * @param int fd
 * @return bool
 */
inline static bool
tvpn_srv_tcp_socket_setup(int fd)
{
  int opt_1 = 1;

  #define SET_XT(LEVEL, OPTNAME, OPTVAL, OPTLEN)               \
    if (setsockopt(fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {  \
      debug_log(0, "Error setsockopt(): %s", strerror(errno)); \
      return false;                                            \
    }

  SET_XT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_XT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_XT
}



/**
 * @param srv_tcp *srv
 * @return bool
 */
inline static bool
tvpn_srv_tcp_init_iface(srv_tcp *srv)
{

  uint16_t       i;
  srv_cfg        *cfg      = srv->cfg;
  tcp_channel    *channels = srv->channels;
  srv_iface_cfg  *iface    = &(cfg->iface);
  const uint16_t max_conn  = cfg->sock.max_conn;


  debug_log(2, "Allocating virtual network interface...");


  for (i = 0; i < max_conn; i++) {
    int fd;

    debug_log(5, "Allocating tun_fd, (seq:%d)...", i);

    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);

    if (fd < 0) {
      debug_log(0, "Cannot allocate network interface: i = %d\n", i);
      goto err;
    }

    /* Set fd to be nonblocking. */
    if (fd_set_nonblock(fd) < 0) {
      debug_log(0, "Error fd_set_nonblock(): %s",
                strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    /* Disable queue. */
    if (tun_set_queue(fd, false) < 0) {
      debug_log(0, "Error tun_set_queue(): %s",
                strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    channels[i].tun_fd = fd;
  }


  return srv_tun_iface_up(iface);

err:
  /* Close opened file descriptors. */

  if (i > 0) {
    debug_log(5, "Closing opened tun_fd(s)...");

    while (i-- > 0) {
      debug_log(5, "Closing tun_fd %d...", i);
      close(channels[i].tun_fd);
      channels[i].tun_fd = -1;
    }
  }

  return false;
}



#endif /* #ifndef SERVER__PLATFORM__LINUX__INIT_H */

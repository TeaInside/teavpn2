
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__INIT_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__INIT_H

/**
 * @param int signal
 * @return void
 */
inline static void
tvpn_server_tcp_signal_handler(int signal)
{
  (void)signal;
  g_state->stop = true;
  __sync_synchronize();
  puts("");
}


/**
 * @param tcp_channel *channels
 * @param uint16_t    n
 * @return void
 */
inline static void
tvpn_server_tcp_init_channels(tcp_channel *channels, uint16_t n)
{
  for (uint16_t i = 0; i < n; i++) {
    tvpn_server_tcp_init_channel(&(channels[i]));
  }
}


/**
 * @param tcp_channel *chan
 * @return void
 */
inline static void
tvpn_server_tcp_init_channel(tcp_channel *chan)
{
  memset(chan, 0, sizeof(tcp_channel));
  chan->cli_fd = -1;
  chan->tun_fd = -1;
}


/**
 * @param tcp_channel *state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *state)
{
  int                fd;
  int                rv;
  struct sockaddr_in server_addr;
  server_socket_cfg  *sock_cfg    = &(state->config->sock);

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
  if (!tvpn_server_tcp_socket_setup(fd)) {
    return false;
  }
  debug_log(5, "Socket file descriptor set up successfully!");

  /*
   * Prepare server bind address data.
   */
  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(sock_cfg->bind_port);
  server_addr.sin_addr.s_addr = inet_addr(sock_cfg->bind_addr);

  /*
   * Bind socket to address.
   */
  rv = bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
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
tvpn_server_tcp_socket_setup(int fd)
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

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__INIT_H */

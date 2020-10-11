
#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX_H
#  error This file must only be included from   \
         teavpn2/client/sock/tcp/client/linux.h
#endif

#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__INIT_H
#define TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__INIT_H


/**
 * @param  int signal
 * @return void
 */
inline static void
tvpn_client_tcp_signal_handler(int signal)
{
  (void)signal;
  printf("\n");
  g_state->stop = true;
}


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool
tvpn_client_tcp_iface_init(client_tcp_state * __restrict__ state)
{
  int               fd;
  client_cfg       *config   = state->config;
  client_iface_cfg *iface    = &(config->iface);


  debug_log(2, "Allocating virtual network interface...");
  debug_log(5, "Allocating tun_fd...");
  fd = tun_alloc(iface->dev, IFF_TUN);

  if (fd < 0) {
    debug_log(0, "Cannot allocate virtual network interface");
    return false;
  }

  if (fd_set_nonblock(fd) < 0) {
    debug_log(0, "Error fd_set_nonblock(): %s", strerror(errno));
    close(fd);
    return false; 
  }

  state->tun_fd = fd;

  return true;
}


/**
 * @param  int *__restrict__ pipe_fd
 * @return bool
 */
inline static bool
tvpn_client_tcp_init_pipe(int *__restrict__ pipe_fd)
{
  register bool ret;

  debug_log(2, "Initializing pipe...");

  ret = (pipe(pipe_fd) != -1);

  if (!ret) {
    debug_log(0, "Error pipe(): %s", strerror(errno));
  }

  return ret;
}


/**
 * @param  int fd
 * @return bool
 */
inline static bool
tvpn_client_tcp_socket_setup(int fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN)            \
    if (setsockopt(fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {     \
      debug_log(0, "Error setsockopt: %s", strerror(errno));      \
      return false;                                               \
    }

  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool
tvpn_client_tcp_sock_init(client_tcp_state * __restrict__ state)
{
  int                  fd           = -1;
  client_socket_cfg   *sock         = &(state->config->sock);
  socklen_t            addrlen      = sizeof(struct sockaddr_in);
  struct sockaddr_in   server_addr;

  /*
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(2, "Creating TCP socket...");
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    debug_log(0, "Socket creation failed: %s", strerror(errno));
    return false;
  }
  debug_log(5, "TCP socket created successfully!");


  /*
   * Setup TCP socket.
   */
  debug_log(2, "Setting up socket file descriptor...");
  if (!tvpn_client_tcp_socket_setup(fd)) {
    return false;
  }
  debug_log(5, "Socket file descriptor set up successfully!");


  /*
   * Prepare server bind address data.
   */
  bzero(&server_addr, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(sock->server_port);
  server_addr.sin_addr.s_addr = inet_addr(sock->server_addr);

  debug_log(0, "Connecting to %s:%d...", sock->server_addr,
            sock->server_port);

  still_connecting:
  if (connect(fd, (struct sockaddr *)&server_addr, addrlen) < 0) {

    register int _errno = errno;

    if (_errno == EINPROGRESS || _errno == EALREADY) {

      if (state->stop) {
        debug_log(0, "Aborted!");
        goto err;
      }

      goto still_connecting;
    }

    debug_log(0, "Error connect(): %s", strerror(_errno));
    goto err;
  }


  debug_log(0, "Connection established!");

  /*
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  state->net_fd = fd;
  return true;

  err:
  if (fd != -1) {
    debug_log(0, "Closing socket descriptor...");
    close(fd);
  }
  return false;
}


#endif /* #ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__INIT_H */

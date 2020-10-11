
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
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
  printf("\n");
  g_state->stop = true;
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_init_channel(tcp_channel *__restrict__ chan)
{
  memset(chan, 0, sizeof(tcp_channel));
  chan->cli_fd = -1;
  chan->tun_fd = -1;
}


/**
 * @param tcp_channel *__restrict__ channels
 * @param uint16_t max_conn
 * @return void
 */
inline static void
tvpn_server_tcp_init_channels(tcp_channel *__restrict__ channels,
                              uint16_t max_conn)
{
  for (register uint16_t i = 0; i < max_conn; i++) {
    tvpn_server_tcp_init_channel(&(channels[i]));
  }
}


/**
 * @param int fd
 * @return bool
 */
bool
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


/**
 * @param  int *__restrict__ pipe_fd
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_pipe(int *__restrict__ pipe_fd)
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
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *__restrict__ state)
{
  register int                rv;
  register int                fd;
  register server_socket_cfg  *sock = &(state->config->sock);

  struct sockaddr_in          server_addr;

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
  server_addr.sin_port        = htons(sock->bind_port);
  server_addr.sin_addr.s_addr = inet_addr(sock->bind_addr);


  /*
   * Bind socket to address.
   */
  rv = bind(fd, (struct sockaddr *)&(server_addr), sizeof(struct sockaddr_in));
  if (rv < 0) {
    debug_log(0, "Error bind(): %s", strerror(errno));
    goto err;
  }


  /*
   * Listen socket.
   */
  if (listen(fd, sock->backlog) < 0) {
    debug_log(0, "Error listen(): %s", strerror(errno));
    goto err;
  }

  debug_log(0, "Listening on %s:%d...", sock->bind_addr, sock->bind_port);

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


#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__INIT_H */

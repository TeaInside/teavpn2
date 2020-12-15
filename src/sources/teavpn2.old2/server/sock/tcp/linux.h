
#ifndef TEAVPN2__SERVER__SOCK__TCP__LINUX_H
#define TEAVPN2__SERVER__SOCK__TCP__LINUX_H

/**
 * @param const char  *bind_addr
 * @param uint16_t    bind_port
 * @param int         backlog
 * @return int
 */
inline static int
ins_srv_init_tcp4(const char *bind_addr, uint16_t bind_port, int backlog)
{
  int                 retval;
  int                 sockfd;
  struct sockaddr_in  srvaddr;

  if (unlikely(bind_addr == NULL)) {
    bind_addr = "0.0.0.0";
  }

  log_printf(5, "Creating TCP socket...");

  sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

  if (unlikely(sockfd < 0)) {
    err_printf("Error creating TCP socket: %s", strerror(errno));
    return -1;
  }

  log_printf(5, "TCP socket created successfully with fd %d", sockfd);


  memset(&srvaddr, 0, sizeof(struct sockaddr_in));
  srvaddr.sin_family      = AF_INET;
  srvaddr.sin_port        = htons(bind_port);
  srvaddr.sin_addr.s_addr = inet_addr(bind_addr);


  retval = bind(sockfd, (struct sockaddr *)&srvaddr,
                sizeof(struct sockaddr_in));

  if (unlikely(retval < 0)) {
    err_printf("Error bind: %s", strerror(errno));
    goto err_close;
  }


  retval = listen(sockfd, backlog);

  if (unlikely(retval < 0)) {
    err_printf("Error listen: %s", strerror(errno));
    goto err_close;
  }


  log_printf(0, "Listening on %s:%d...", bind_addr, bind_port);

  return sockfd;

err_close:
  log_printf(5, "Closing TCP file descriptor (%d)...", sockfd);
  close(sockfd);
  return -1;
}


/**
 * @param int          sock_fd
 * @param srv_sock_cfg *cfg
 * @return bool
 */
inline static bool
ins_srv_set_tcp4(int sockfd, srv_sock_cfg *sock)
{
  int opt_1 = 1;

  /* TODO: Handle TCP nodelay and many more from the config. */
  (void)sock;

  #define SETX(LEVEL, OPTNAME, OPTVAL, OPTLEN)                     \
    if (setsockopt(sockfd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {  \
      err_printf("Error setsockopt(): %s", strerror(errno));       \
      return false;                                                \
    }

  SETX(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(int));
  SETX(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(int));

  return true;
  #undef SETX
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__LINUX_H */

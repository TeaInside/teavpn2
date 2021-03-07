
#if !defined(__linux__)
#  error This code is supposed to be compiled only for Linux.
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__IFACE_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__IFACE_H

/**
 * @param server_tcp_state *state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_iface(server_tcp_state *state)
{
  server_cfg        *config   = state->config;
  tcp_channel       *channels = state->channels;
  server_iface_cfg  *iface    = &(config->iface);
  const uint16_t    max_conn  = config->sock.max_conn;
  uint16_t          i;

  debug_log(2, "Allocating virtual network interface...");

  for (i = 0; i < max_conn; i++) {
    int fd;

    debug_log(5, "Allocating tun_fd, (seq:%d)...", i);

    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);

    if (fd < 0) {
      debug_log(0, 
        "Cannot allocate virtual network interface: i = %d\n", i);
      goto err;
    }

    if (fd_set_nonblock(fd) < 0) {
      debug_log(0, "Error fd_set_nonblock(): %s", strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    if (tun_set_queue(fd, false) < 0) {
      debug_log(0, "Error tun_set_queue(): %s", strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    channels[i].tun_fd = fd;
  }

  return server_tun_iface_up(iface);

  err:
  /* Close opened file descriptors. */
  if (i) {
    debug_log(5, "Closing opened tun_fd(s)...");

    while (i--) {
      debug_log(5, "Closing tun_fd %d...", i);
      close(channels[i].tun_fd);
      channels[i].tun_fd = -1;
    }
  }

  return false;
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__IFACE_H */

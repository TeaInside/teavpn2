
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__IFACE_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__IFACE_H


/**
 * @param server_tcp_state *__restrict__ state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_iface(server_tcp_state *__restrict__ state)
{
  register server_cfg        *config   = state->config;
  register tcp_channel       *channels = state->channels;
  register server_iface_cfg  *iface    = &(config->iface);
  register uint16_t          i         = 0;
  const uint16_t             max_conn  = config->sock.max_conn;


  debug_log(2, "Allocating virtual network interface...");

  for (i = 0; i < max_conn; i++) {
    register int fd;

    debug_log(5, "Allocating tun_fd, (seq:%d)...", i);

    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);
    if (fd < 0) {
      debug_log(0, 
        "Cannot allocate virtual network interface: i = %d\n", i);
      goto err;
    }

    if (fd_set_nonblock(fd) < 0) {
      debug_log(0, "Error fd_set_nonblock(): %s", strerror(errno));
      close(fd);
      goto err;
    }

    if (tun_set_queue(fd, false) < 0) {
      debug_log(0, "Error tun_set_queue(): %s", strerror(errno));
      close(fd);
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


#ifndef SRC_TEAVPN2__SERVERTEAVPN2__IFACE__LINUX_H
#define SRC_TEAVPN2__SERVERTEAVPN2__IFACE__LINUX_H

#include <teavpn2/global/helpers/iface.h>

/**
 * @param tcp_state *state
 * @return bool
 */
inline static bool
tsrv_init_tun_fd_tcp(tcp_state *state)
{

  uint16_t       i;
  srv_cfg        *cfg     = state->cfg;
  tcp_channel    *chan    = state->chan;
  srv_iface_cfg  *iface   = &(cfg->iface);
  const uint16_t max_conn = cfg->sock.max_conn;

  log_printf(2, "Allocating virtual network interface...");

  for (i = 0; i < max_conn; i++) {
    int fd;

    log_printf(5, "Allocating tun_fd, (seq:%d)...", i);

    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);

    if (fd < 0) {
      log_printf(0, "Cannot allocate network interface: i = %d", i);
      goto err;
    }

    /* Set fd to be nonblocking. */
    if (fd_set_nonblock(fd) < 0) {
      log_printf(0, "Error fd_set_nonblock(): %s", strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    /* Disable queue. */
    if (tun_set_queue(fd, false) < 0) {
      log_printf(0, "Error tun_set_queue(): %s", strerror(errno));
      close(fd); /* Close current fd. */
      goto err;
    }

    chan[i].tun_fd = fd;
  }


  return true;

err:
  /* Close opened file descriptors. */
  if (i > 0) {
    log_printf(5, "Closing opened tun_fd(s)...");

    while (i-- > 0) {
      log_printf(5, "Closing tun_fd %d...", i);
      close(chan[i].tun_fd);
      chan[i].tun_fd = -1;
    }
  }

  return false;
}

#endif /* #ifndef SRC_TEAVPN2__SERVERTEAVPN2__IFACE__LINUX_H */

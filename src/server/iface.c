
#include <stdio.h>
#include <error.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn2/server/iface.h>
#include <teavpn2/server/common.h>

static int tun_alloc(char *dev, int flags);

/**
 * @param char *dev
 * @return int
 */
int teavpn_iface_allocate(char *dev)
{
  int tun_fd;
  tun_fd = tun_alloc(dev, IFF_TUN);
  if (tun_fd < 0) {
    perror("Error tun_alloc");
    return tun_fd;
  }

  return tun_fd;
}

/**
 * Initialize network interface for TeaVPN server.
 *
 * @param server_config *config
 * @return bool
 */
static bool teavpn_tcp_server_init_iface(server_config *config)
{
}

/**
 * @param char *dev
 * @param int flags
 * @return int
 */
static int tun_alloc(char *dev, int flags)
{
  int fd, err;
  struct ifreq ifr;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);
  return fd;
}
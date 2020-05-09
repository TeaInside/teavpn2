
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

#include <teavpn2/global/iface.h>
#include <teavpn2/global/common.h>

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
bool teavpn_iface_init(struct teavpn_iface *iface)
{
  register size_t arena_pos = 0;
  register size_t l;
  char cmd1[100], cmd2[100], _arena[100],
    *dev,
    *inet4,
    *inet4_bc,
    *arena = _arena;

  dev = escape_sh(arena, iface->dev, strlen(iface->dev));
  arena += strlen(dev) + 1;
  inet4 = escape_sh(arena, iface->inet4, strlen(iface->inet4));
  arena += strlen(inet4) + 1;
  inet4_bc = escape_sh(arena, iface->inet4_bcmask, strlen(iface->inet4_bcmask));

  debug_log(5, "dev: %s", dev);
  debug_log(5, "inet4: %s", inet4);
  debug_log(5, "inet4_bc: %s", inet4_bc);

  sprintf(cmd1, "/sbin/ip link set dev %s up mtu %d", dev, iface->mtu);
  sprintf(cmd2, "/sbin/ip addr add dev %s %s broadcast %s", dev, inet4, inet4_bc);

  debug_log(0, "Executing: %s", cmd1);
  if (system(cmd1)) {
    return false;
  }

  debug_log(0, "Executing: %s", cmd2);
  if (system(cmd2)) {
    return false;
  }

  return true;
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

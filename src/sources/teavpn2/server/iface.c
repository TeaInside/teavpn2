
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn2/server/common.h>

/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt */

int tun_alloc_mq(char *dev, int queues, int *fds)
{
  int fd, ret, i;
  struct ifreq ifr;

  if (!dev) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Fill the interface name. */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
   */
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;

  for (i = 0; i < queues; i++) {

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
      printf("Error open(/dev/net/tun): %s\n", strerror(errno));
      goto err;
    }

    if ((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
      printf("Error ioctl(%d, TUNSETIFF): %s\n", fd, strerror(errno));
      close(fd);
      goto err;
    }

    fds[i] = fd;
  }


  return 0;

err:

  /* Close opened fds. */
  for (--i; i >= 0; i--) {
    close(fds[i]);
  }

  return ret;
}

int tun_set_queue(int fd, int enable)
{
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));

  if (enable)
    ifr.ifr_flags = IFF_ATTACH_QUEUE;
  else
    ifr.ifr_flags = IFF_DETACH_QUEUE;

  return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

#define IFACE_CMD(CMD, ...)       \
  sprintf(cmd, CMD, __VA_ARGS__); \
  if (system(cmd)) {              \
    return -1;                    \
  }

int iface_up(server_iface_cfg *iface)
{
  char
    cmd[256],
    dev[16],
    ipv4[sizeof("xxx.xxx.xxx.xxx/xx")],
    ipv4_bcmask[sizeof("xxx.xxx.xxx.xxx")];

  escapeshellarg(dev, iface->dev);
  escapeshellarg(ipv4, iface->ipv4);
  escapeshellarg(ipv4_bcmask, iface->ipv4_bcmask);

  IFACE_CMD("/sbin/ip link set dev %s up mtu %d", dev, iface->mtu);
  IFACE_CMD("/sbin/ip addr add dev %s %s broadcast %s", dev, ipv4, ipv4_bcmask);

  return 0;
}

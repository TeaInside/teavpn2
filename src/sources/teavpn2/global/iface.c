
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>


#include <teavpn2/global/common.h>

/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt */

/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */

int tun_alloc(char *dev, int flags)
{
  int fd, ret;
  struct ifreq ifr;

  if (!dev) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Fill the interface name. */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  ifr.ifr_flags = flags;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    printf("Error open(/dev/net/tun): %s\n", strerror(errno));
    return fd;
  }

  if ((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    printf("Error ioctl(%d, TUNSETIFF): %s\n", fd, strerror(errno));
    close(fd);
    return ret;
  }

  return fd;
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

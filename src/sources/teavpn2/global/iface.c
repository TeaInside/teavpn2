
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
    debug_log(0, "Error open(/dev/net/tun): %s", strerror(errno));
    return fd;
  }

  if ((ret = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    debug_log(0, "Error ioctl(%d, TUNSETIFF): %s", fd, strerror(errno));
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

uint8_t cidr_jump_table(__be32 netmask) {
  switch (netmask) {
    case 0b1: return 1;
    case 0b11: return 2;
    case 0b111: return 3;
    case 0b1111: return 4;
    case 0b11111: return 5;
    case 0b111111: return 6;
    case 0b1111111: return 7;
    case 0b11111111: return 8;
    case 0b111111111: return 9;
    case 0b1111111111: return 10;
    case 0b11111111111: return 11;
    case 0b111111111111: return 12;
    case 0b1111111111111: return 13;
    case 0b11111111111111: return 14;
    case 0b111111111111111: return 15;
    case 0b1111111111111111: return 16;
    case 0b11111111111111111: return 17;
    case 0b111111111111111111: return 18;
    case 0b1111111111111111111: return 19;
    case 0b11111111111111111111: return 20;
    case 0b111111111111111111111: return 21;
    case 0b1111111111111111111111: return 22;
    case 0b11111111111111111111111: return 23;
    case 0b111111111111111111111111: return 24;
    case 0b1111111111111111111111111: return 25;
    case 0b11111111111111111111111111: return 26;
    case 0b111111111111111111111111111: return 27;
    case 0b1111111111111111111111111111: return 28;
    case 0b11111111111111111111111111111: return 29;
    case 0b111111111111111111111111111111: return 30;
    case 0b1111111111111111111111111111111: return 31;
    case 0b11111111111111111111111111111111: return 32;
    /* Invalid. */
    default: return 0;
  }
}

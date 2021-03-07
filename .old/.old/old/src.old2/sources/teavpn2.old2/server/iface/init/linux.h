
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*
 * https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */


/**
 * @param char *dev
 * @param int  flags
 * @return int
 */
int
tun_alloc(char *dev, int flags)
{
  int          fd;
  int          ret;
  struct ifreq ifr;

  if (dev == NULL) {
    err_printf("Error: tun_alloc(): dev cannot be NULL");
    return -1;
  }

  if (*dev == '\0') {
    err_printf("Error: tun_alloc(): dev cannot be empty");
    return -1;
  }

  memset(&ifr, 0, sizeof(struct ifreq));

  strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
  ifr.ifr_flags = flags;


  fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0) {
    err_printf("Error: open(/dev/net/tun): %s", strerror(errno));
    return fd;
  }


  ret = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (ret < 0) {
    err_printf("Error: ioctl(%d, TUNSETIFF): %s", fd, strerror(errno));
    close(fd);
    return ret;
  }

  return fd;
}


int
tun_set_queue(int fd, bool enable)
{
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_flags = enable ? IFF_ATTACH_QUEUE : IFF_DETACH_QUEUE;

  return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
}

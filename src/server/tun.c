
/*
 * @see https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/**
 * @param char *dev
 * @param int  queues
 * @param int  *fds
 * @return int
 */
int tun_alloc_mq(char *dev, int queues, int *fds)
{
  struct ifreq ifr;
  int fd, err, i;

  if (!dev)
    return -1;

  memset(&ifr, 0, sizeof(ifr));
  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
   */
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
  strcpy(ifr.ifr_name, dev);

  for (i = 0; i < queues; i++) {
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
      goto err;
    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err) {
      close(fd);
      goto err;
    }
    fds[i] = fd;
  }

  return 0;
err:
  for (--i; i >= 0; i--)
    close(fds[i]);
  return err;
}

/**
 * @param int fd
 * @param int enable
 * @return int
 */
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

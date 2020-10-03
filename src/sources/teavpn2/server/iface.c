
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>

static const char err_open[]  = "open()";
static const char err_ioctl[] = "ioctl()";

int tun_alloc_mq(char *dev, int queues, int *fds)
{
  const char *errcall;
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
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
      errcall = err_open;
      goto err;
    }

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);

    if (err) {
      errcall = err_ioctl;
      close(fd);
      goto err;
    }

    fds[i] = fd;
  }

  return 0;

err:
  perror(errcall);
  for (--i; i >= 0; i--)
    close(fds[i]);
  return err;
}

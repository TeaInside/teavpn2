
#ifndef SRC_TEAVPN2__GLOBAL__HELPERS__FD__LINUX_H
#define SRC_TEAVPN2__GLOBAL__HELPERS__FD__LINUX_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <teavpn2/global/helpers/fd.h>

/**
 * @param int fd
 * @return int
 */
int
fd_set_nonblock(int fd)
{
  int flags;
/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
  /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
  flags = fcntl(fd, F_GETFL, 0);
  if (-1 == flags) {
    flags = 0;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
  /* Otherwise, use the old way of doing it */
  flags = 1;
  return ioctl(fd, FIOBIO, &flags);
#endif
}

#endif /* #ifndef SRC_TEAVPN2__GLOBAL__HELPERS__FD__LINUX_H */

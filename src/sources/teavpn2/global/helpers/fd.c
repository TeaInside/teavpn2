
#include <fcntl.h>
#include <sys/ioctl.h>

#include <teavpn2/global/helpers/fd.h>


int
fd_set_nonblock(int fd)
{
  int flags;
/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
  /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
  if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
    flags = 0;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
  /* Otherwise, use the old way of doing it */
  flags = 1;
  return ioctl(fd, FIOBIO, &flags);
#endif
}

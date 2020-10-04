
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include <teavpn2/global/common.h>

int fd_set_nonblock(int fd)
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

char *escapeshellarg(char *alloc, char *str)
{
  size_t x, y = 0;
  size_t l = strlen(str);
  char *cmd;

  if (!alloc) {
    cmd = (char *)malloc(sizeof(char) * l * 4); // Worst case
  } else {
    cmd = alloc;
  }

#ifdef PHP_WIN32
  cmd[y++] = '"';
#else
  cmd[y++] = '\'';
#endif

  for (x = 0; x < l; x++) {
    switch (str[x]) {
#ifdef PHP_WIN32
    case '"':
    case '%':
    case '!':
      cmd[y++] = ' ';
      break;
#else
    case '\'':
      cmd[y++] = '\'';
      cmd[y++] = '\\';
      cmd[y++] = '\'';
#endif
    /* fall-through */
    default:
      cmd[y++] = str[x];
    }
  }
#ifdef PHP_WIN32
  if (y > 0 && '\\' == cmd[y - 1]) {
    int k = 0, n = y - 1;
    for (; n >= 0 && '\\' == cmd[n]; n--, k++);
    if (k % 2) {
      cmd[y++] = '\\';
    }
  }

  cmd[y++] = '"';
#else
  cmd[y++] = '\'';
#endif
  cmd[y] = '\0';

  return cmd;
}

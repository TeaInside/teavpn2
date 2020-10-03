
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <teavpn2/global/common.h>

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

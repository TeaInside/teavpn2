
#include <string.h>
#include <stdlib.h>

#include <teavpn2/global/helpers.h>

/**
 * @param char *str
 * @return char *
 */
char *escape_sh(
  register char *cmd, /* arena */
  register char *str, /* string to be escaped */
  register size_t l   /* string length */
)
{
  register size_t x;
  register size_t y = 0;

  // cmd = (char *)malloc(sizeof(char) * l * 4); // Worst case

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

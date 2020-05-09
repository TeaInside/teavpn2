
#include <string.h>

#include <teavpn2/global/arena.h>
#include <teavpn2/global/helpers.h>

/**
 * @param char *str
 * @return char *
 */
char *escapeshellarg(char *str)
{
  size_t x, y = 0;
  size_t l = strlen(str);
  char *cmd;

  cmd = (char *)arena_alloc(sizeof(char) * l * 4); // Worst case

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

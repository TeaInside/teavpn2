
#include <stdio.h>
#include <teavpn/server/common.h>

/**
 * @param int    argc
 * @param char   **argv
 * @param char   **envp
 * @param server *arg
 * @return bool
 */
bool teavpn_server_arg_parser(int argc, char **argv, char *envp, server_arg *arg)
{
  bool ret = false;

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    goto ret;
  }


ret:
  return ret;
}

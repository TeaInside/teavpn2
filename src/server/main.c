
#include <teavpn/server/common.h>

/**
 * @param int  argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp)
{
  server_arg arg;

  debug_log(2, "Hello World!");

  if (!teavpn_server_arg_parser(argc, argv, envp, &arg)) {
    return 1;
  }
  

  return 0;
}



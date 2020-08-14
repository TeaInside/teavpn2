
#include <teavpn/server/common.h>

/**
 * @param int  argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  server_config config;

  if (!teavpn_server_arg_parser(argc, argv, envp, &config)) {
    return 1;
  }

  return teavpn_server_run(&config);
}

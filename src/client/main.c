
#include <teavpn/client/common.h>

/**
 * @param int  argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  client_config config;

  if (!teavpn_client_arg_parser(argc, argv, envp, &config)) {
    return 1;
  }

  return teavpn_client_run(&config);
}

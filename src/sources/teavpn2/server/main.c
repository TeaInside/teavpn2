
#include <stdio.h>
#include <stdlib.h>

#include <teavpn2/server/common.h>


int main(int argc, char *argv[], char *envp[])
{
  server_config config;

  if (!tvpn_server_argv_parse(argc, argv, envp, &config)) {
    return 1;
  }



  return 0;
}

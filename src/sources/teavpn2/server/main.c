
#include <stdio.h>
#include <stdlib.h>

#include <teavpn2/server/common.h>


int main(int argc, char *argv[], char *envp[])
{
  server_cfg config;

  if (!tvpn_server_argv_parse(argc, argv, envp, &config)) {
    return 1;
  }

  if (config.config_file) {
    if (!tvpn_server_load_config_file(config.config_file, &config)) {
      return 1;
    }
  }

  return 0;
}

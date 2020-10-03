
#include <stdio.h>

#include <teavpn2/client/common.h>

#ifndef ARENA_SIZE
#define ARENA_SIZE 4096
#endif


int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE];
  client_cfg config;

  t_ar_init(arena, sizeof(arena));

  if (!tvpn_client_argv_parse(argc, argv, envp, &config)) {
    return 1;
  }

  if (config.config_file) {
    if (!tvpn_client_load_config_file(config.config_file, &config)) {
      return 1;
    }
  }

  return 0;
}

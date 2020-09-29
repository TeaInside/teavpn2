
#include <stdio.h>
#include <stdlib.h>

#include <teavpn2/server/common.h>

#ifndef ARENA_SIZE
#define ARENA_SIZE 4096
#endif


int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE];
  server_cfg config;

  t_ar_init(arena, sizeof(arena));

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

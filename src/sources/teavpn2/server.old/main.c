
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/common.h>

#ifndef ARENA_SIZE
#define ARENA_SIZE 4096
#endif

/**
 * @param int   argc
 * @param char  *argv[]
 * @param char  *envp[]
 * @return int
 */
int
main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE];
  server_cfg config;


  /* Init stack arena allocator. */
  t_ar_init(arena, sizeof(arena));


  /* Parse program arguments. */
  if (!tvpn_server_argv_parse(argc, argv, envp, &config)) {
    return 1;
  }


  if (config.config_file) {
    /* Parse config file. */
    if (!tvpn_server_load_config_file(config.config_file, &config)) {
      return 1;
    }
  }

  return tvpn_server_run(&config);
}

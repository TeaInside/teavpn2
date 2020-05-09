
#include <stdio.h>
#include <teavpn2/server/common.h>

#define ARENA_SIZE (1024 * 100)

int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE]; /* We create our function to treat this like heap. */
  teavpn_server_config config;

  if (!teavpn_server_argv_parser(argc, argv, envp, &config)) {
    return 1;
  }

  init_arena(arena, ARENA_SIZE);

  if (config.config_file != NULL) {
    if (!teavpn_server_config_parser(config.config_file, &config)) {
      return 1;
    }
  }

  #ifdef TEAVPN_DEBUG
    print_server_config(&config);
  #endif

  return teavpn_server_run(&config);
}


#include <teavpn2/client/common.h>

#define ARENA_SIZE (1024 * 50)

/**
 * @param int argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE]; /* We create our function to treat this like heap. */
  teavpn_client_config config;

  if (!teavpn_client_argv_parser(argc, argv, envp, &config)) {
    return 1;
  }

  init_arena(arena, ARENA_SIZE);

  if (config.config_file != NULL) {
    if (!teavpn_client_config_parser(config.config_file, &config)) {
      return 1;
    }
  }

  #ifdef TEAVPN_DEBUG
    print_client_config(&config);
  #endif

  return teavpn_client_run(&config);
}

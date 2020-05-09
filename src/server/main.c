
#include <stdio.h>
#include <teavpn2/server/common.h>

#define ARENA_SIZE (1024 * 100)

int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE]; /* We create our function to treat this like heap. */
  teavpn_server_config config;

  if (argc != 2) {
    printf("Invalid arguments!\n");
    printf("Usage: %s <config_file>\n", argv[0]);
    return 1;
  }

  init_arena(arena, ARENA_SIZE);

  if (!teavpn_server_config_parser(argv[1], &config)) {
    return 1;
  }

  #ifdef TEAVPN_DEBUG
    print_server_config(&config);
  #endif

  return 0;
}

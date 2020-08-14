
#include <teavpn/server/common.h>

#define ARENA_SIZE (1024 * 1024)

/**
 * @param int  argc
 * @param char *argv[]
 * @param char *envp[]
 * @return int
 */
int main(int argc, char *argv[], char *envp[])
{
  char arena[ARENA_SIZE];
  server_config config;

  init_stack_arena((void *)arena, ARENA_SIZE);

  if (!teavpn_server_arg_parser(argc, argv, envp, &config)) {
    return 1;
  }

  return teavpn_server_run(&config);
}

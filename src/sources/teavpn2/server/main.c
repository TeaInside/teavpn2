

#include <teavpn2/server/common.h>
#include <teavpn2/server/argv.h>
#include <teavpn2/server/helpers.h>


#ifndef ARENA_SIZE
#define ARENA_SIZE (4096)
#endif

int
main(int argc, char *argv[])
{
  int     ret;
  srv_cfg cfg;
  char    arena[ARENA_SIZE];


  ar_init(arena, ARENA_SIZE);

  if (!tsrv_argv_parser(argc, argv, &cfg)) {
    ret = 1;
    goto ret;
  }

  ret = tsrv_run(&cfg);






ret:
  return ret;
}

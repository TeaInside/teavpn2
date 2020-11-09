

#include <teavpn2/server/common.h>
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

  /* Load config from the program arguments. */
  if (!tsrv_argv_parser(argc, argv, &cfg)) {
    ret = 1;
    goto ret;
  }


  /* Load config from the config file. */
  if (cfg.cfg_file != NULL) {
    if (!tsrv_cfg_load(cfg.cfg_file, &cfg)) {
      ret = 1;
      goto ret;
    }
  }

  print_cfg(&cfg);

  ret = tsrv_run(&cfg);

ret:
  tsrv_clean_up();
  return ret;
}

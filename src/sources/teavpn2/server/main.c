
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/argv.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/teavpn2.h>

#ifndef ARENA_SIZE
#define ARENA_SIZE 4096
#endif

/**
 * @param int   argc
 * @param char  *argv[]
 * @return int
 */
int
main(int argc, char *argv[])
{
  int     ret;
  srv_cfg cfg;
  char    arena[ARENA_SIZE];

  memset(arena, 0, sizeof(arena));
  t_ar_init(arena, sizeof(arena));

  ret = 0;

  tvpn_add_log_stream(stdout);

  if (!tvpn_srv_argv_parse(argc, argv, &cfg)) {
    ret = 1;
    goto ret;
  }

  if (!tvpn_srv_load_cfg_file(cfg.config_file, &cfg)) {
    ret = 1;
    goto ret;
  }

  ret = tvpn_srv_run(&cfg);

ret:
  tvpn_clean_log_stream();
  return ret;
}

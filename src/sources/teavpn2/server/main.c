
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/common.h>


/**
 * @param int  argc
 * @param char *argv
 * @return int
 */
int
tsrv_start(int argc, char *argv[])
{
  int retval = 1;
  srv_cfg cfg;


  if (!tsrv_argv_parser(argc, argv, &cfg)) {
    goto ret;
  }


  if (cfg.cfg_file != NULL) {
    if (!tsrv_cfg_load(cfg.cfg_file, &cfg)) {
      goto ret;
    }
  }

  print_srv_cfg(&cfg);

  retval = tsrv_run(&cfg);

ret:
  return retval;
}

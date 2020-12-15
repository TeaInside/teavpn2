
#include <stdio.h>
#include <string.h>

#include <teavpn2/client/common.h>


/**
 * @param int  argc
 * @param char *argv
 * @return int
 */
int
tcli_start(int argc, char *argv[])
{
  int retval = 1;
  cli_cfg cfg;


  if (!tcli_argv_parser(argc, argv, &cfg)) {
    goto ret;
  }


  if (cfg.cfg_file != NULL) {
    if (!tcli_cfg_load(cfg.cfg_file, &cfg)) {
      goto ret;
    }
  }

  print_cli_cfg(&cfg);

ret:
  return retval;
}


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <teavpn2/server/common.h>

#ifndef PARAM_DEBUG
#define PARAM_DEBUG 1
#else

#if PARAM_DEBUG
  #define PRINT_PARAM(CONFIG_NAME, VAL_LT, VAL) \
    printf("  "#CONFIG_NAME" = "VAL_LT"\n", VAL)
#else
  #define PRINT_PARAM(CONFIG_NAME, VAL_LT, VAL)
#endif


const static struct option long_options[] = {
  /* Interface options. */  
  {"config",       required_argument, 0, 'c'},
  {"dev",          required_argument, 0, 'd'},
  {"mtu",          required_argument, 0, 'm'},
  {"inet4",        required_argument, 0, '4'},
  {"inet4-bcmask", required_argument, 0, 'b'},
  {"sock-type",    required_argument, 0, 's'},

  /* Socket options. */
  {"bind-addr",    required_argument, 0, 'H'},
  {"bind-port",    required_argument, 0, 'P'},

  /* Data directory. */
  {"data-dir",     required_argument, 0, 'u'},

  {0, 0, 0, 0}
};


inline static void set_default_config(tvpn_server_config *config);


/**
 * Return false if parse fails.
 */
bool tvpn_server_argv_parse(
  int argc,
  char **argv,
  char **envp,
  tvpn_server_config *config
)
{

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }


}


/**
 * Initialize default config values.
 */
inline static void set_default_config(tvpn_server_config *config)
{

}


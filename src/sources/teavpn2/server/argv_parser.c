
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#include <teavpn2/server/common.h>

#ifndef ARGV_DEBUG
#define ARGV_DEBUG 1
#endif

#if ARGV_DEBUG
  #define PRINT_CONFIG(CONFIG_NAME, VAL_LT, VAL) \
    printf("  "#CONFIG_NAME" = "VAL_LT"\n", VAL)
#else
  #define PRINT_CONFIG(CONFIG_NAME, VAL_LT, VAL)
#endif

inline static void set_default_config(server_config *config);
inline static bool getopt_handler(int argc, char **argv, server_config *config);

/**
 * Return false if parse fails.
 */
bool tvpn_server_argv_parse(
  int argc,
  char *argv[],
  char *envp[],
  server_config *config
)
{

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }

  set_default_config(config);
  return getopt_handler(argc, argv, config);
}


/**
 * Initialize default config values.
 */
inline static void set_default_config(server_config *config)
{

}

const static struct option long_options[] = {
  /* Interface options. */
  {"config",       required_argument, 0, 'c'},
  {"dev",          required_argument, 0, 'd'},
  {"mtu",          required_argument, 0, 'm'},
  {"ipv4",         required_argument, 0, '4'},
  {"ipv4-bcmask",  required_argument, 0, 'b'},
  {"sock-type",    required_argument, 0, 's'},

  /* Socket options. */
  {"bind-addr",    required_argument, 0, 'H'},
  {"bind-port",    required_argument, 0, 'P'},

  /* Data directory. */
  {"data-dir",     required_argument, 0, 'u'},

  {0, 0, 0, 0}
};

/**
 * Parse the arguments and plug it to config.
 */
inline static bool getopt_handler(int argc, char **argv, server_config *config)
{
  int c;

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    c = getopt_long(argc, argv, "c:d:m:4:b:s:H:P:u:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      /* Interface options. */
      case 'c':
        config->config_file = optarg;
        PRINT_CONFIG(config->config_file, "\"%s\"", optarg);
        break;
      case 'd':
        config->iface.dev = optarg;
        PRINT_CONFIG(config->iface.dev, "\"%s\"", optarg);
        break;
      case 'm':
        config->iface.mtu = (uint16_t)atoi(optarg);
        PRINT_CONFIG(config->iface.mtu, "%d", config->iface.mtu);
        break;
      case '4':
        config->iface.ipv4 = optarg;
        PRINT_CONFIG(config->iface.ipv4, "\"%s\"", optarg);
        break;
      case 'b':
        config->iface.ipv4_bcmask = optarg;
        PRINT_CONFIG(config->iface.ipv4_bcmask, "\"%s\"", optarg);
        break;
    }
  }
}

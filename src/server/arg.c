
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <teavpn/server/common.h>

#ifndef DEBUG_GETOPT
#define DEBUG_GETOPT 1
#endif

inline static void set_default_config(server_config *config);
inline static bool getopt_handler(int argc, char **argv, server_config *config);

/**
 * @param int             argc
 * @param char            **argv
 * @param char            **envp
 * @param server_config   *config
 * @return bool
 */
bool teavpn_server_arg_parser(int argc, char **argv, char **envp, server_config *config)
{
  if (argc == 1) {
    error_log("Usage: %s [options]", argv[0]);
    return false;
  }

  set_default_config(config);
  return getopt_handler(argc, argv, config);
}

/**
 * @param server_config *config
 * @return void
 */
inline static void set_default_config(server_config *config)
{
  config->config_file    = NULL;
  config->data_dir       = NULL;

  /*
   * Socket communication configuration.
   */
  config->bind_addr      = (char *)"0.0.0.0";
  config->bind_port      = 55555;
  config->backlog        = 10; 
  config->sock_type      = TEAVPN_SOCK_TCP;

  /*
   * Virtual network interface configuration.
   */
  config->net.dev            = (char *)"tuns0";
  config->net.inet4          = NULL;
  config->net.inet4_bcmask   = NULL;
  config->net.mtu            = 1500;
}

const static struct option long_options[] = {
  {"config",       required_argument, 0, 'c'},
  {"data-dir",     required_argument, 0, 'u'},

  /*
   * Socket communication configuration.
   */
  {"bind-addr",    required_argument, 0, 'h'},
  {"bind-port",    required_argument, 0, 'p'},
  {"backlog",      required_argument, 0, 'B'},
  {"sock-type",    required_argument, 0, 's'},

  /*
   * Virtual network interface configuration.
   */
  {"dev",          required_argument, 0, 'd'},
  {"mtu",          required_argument, 0, 'm'},
  {"inet4",        required_argument, 0, '4'},
  {"inet4-bcmask", required_argument, 0, 'b'},

  {0,           0,            0,           0}
};

#if DEBUG_GETOPT
  #define pdebug(...) error_log(__VA_ARGS__)
#else
  #define pdebug(...)
#endif

/**
 * @param int            argc
 * @param char           **argv
 * @param server_config  *config
 * @return bool
 */
inline static bool getopt_handler(int argc, char **argv, server_config *config)
{
  int c;

  pdebug("Parsing argv...");

  while (1) {
    // int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    c = getopt_long(argc, argv, "c:u:h:p:s:d:m:4:b:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'c':
        config->config_file = optarg;
        break;

      case 'u':
        config->data_dir = optarg;
        break;


      /*
       * Socket communication configuration.
       */
      case 'h':
        config->bind_addr = optarg;
        break;

      case 'p':
        config->bind_port = (uint16_t)atoi(optarg);
        break;

      case 'B':
        config->backlog = (int)atoi(optarg);
        break;

      case 's':
        if (!strcmp(optarg, "tcp")) {
          config->sock_type = TEAVPN_SOCK_TCP;
        } else if (!strcmp(optarg, "udp")) {
          config->sock_type = TEAVPN_SOCK_UDP;
        } else {
          return false;
        }
        break;


      /*
       * Virtual network interface configuration.
       */
      case 'd':
        config->net.dev = optarg;
        break;

      case 'm':
        config->net.mtu = (uint32_t)atoi(optarg);
        break;

      case '4':
        config->net.inet4 = optarg;
        break;

      case 'b':
        config->net.inet4_bcmask = optarg;
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        return false;
        break;
    }
  }

  return true;
}

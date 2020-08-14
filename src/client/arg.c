
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <teavpn/client/common.h>

#define DEBUG_GETOPT 1

inline static void set_default_config(client_config *config);
inline static bool getopt_handler(int argc, char **argv, client_config *config);

/**
 * @param int             argc
 * @param char            **argv
 * @param char            **envp
 * @param client_config   *config
 * @return bool
 */
bool teavpn_client_arg_parser(int argc, char **argv, char **envp, client_config *config)
{
  if (argc == 1) {
    error_log("Usage: %s [options]", argv[0]);
    return false;
  }

  set_default_config(config);
  return getopt_handler(argc, argv, config);
}

/**
 * @param client_config *config
 * @return void
 */
inline static void set_default_config(client_config *config)
{
  config->config_file    = NULL;

  /*
   * Socket communication configuration.
   */
  config->server_addr    = NULL;
  config->server_port    = 55555;
  config->sock_type      = TEAVPN_SOCK_TCP;

  /*
   * Virtual network interface configuration.
   */
  config->net.dev            = (char *)"tunc0";
  config->net.inet4          = NULL;
  config->net.inet4_bcmask   = NULL;
  config->net.mtu            = 1500;

  /*
   * Authentication.
   */
  config->username           = NULL;
  config->password           = NULL;
}

const static struct option long_options[] = {
  {"config",         required_argument, 0, 'c'},

  /*
   * Socket communication configuration.
   */
  {"client-addr",    required_argument, 0, 'h'},
  {"client-port",    required_argument, 0, 'p'},
  {"sock-type",      required_argument, 0, 's'},

  /*
   * Virtual network interface configuration.
   */
  {"dev",            required_argument, 0, 'd'},
  {"mtu",            required_argument, 0, 'm'},

  /*
   * Authentication.
   */
  {"username",       required_argument, 0, 'u'},
  {"password",       required_argument, 0, 'P'},

  {0,            0,             0,           0}
};

#if DEBUG_GETOPT
  #define pdebug(...) error_log(__VA_ARGS__)
#else
  #define pdebug(...)
#endif

/**
 * @param int            argc
 * @param char           **argv
 * @param client_config  *config
 * @return bool
 */
inline static bool getopt_handler(int argc, char **argv, client_config *config)
{
  int c;

  pdebug("Parsing argv...");

  while (1) {
    // int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    c = getopt_long(argc, argv, "c:h:p:s:d:m:u:P:", long_options, &option_index);

    if (c == -1)
      break;

    switch (c) {
      case 'c':
        config->config_file = optarg;
        break;

      /*
       * Socket communication configuration.
       */
      case 'h':
        config->server_addr = optarg;
        break;

      case 'p':
        config->server_port = (uint16_t)atoi(optarg);
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


     /*
      * Authentication.
      */
      case 'u':
        config->username = optarg;
        break;

      case 'P':
        config->password = optarg;
        break;

      default:
        printf("?? getopt returned character code 0%o ??\n", c);
        return false;
        break;
    }
  }

  return true;
}

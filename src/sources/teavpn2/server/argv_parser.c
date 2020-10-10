
#include <ctype.h>
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
#  define PRINT_CONFIG(CONFIG_NAME, VAL_LT, VAL) \
    printf("  "#CONFIG_NAME" = "VAL_LT"\n", VAL)
#else
#  define PRINT_CONFIG(CONFIG_NAME, VAL_LT, VAL)
#endif

inline static
void show_help(char *app);

inline static
void set_default_config(server_cfg *config);

inline static
bool getopt_handler(int argc, char **argv, server_cfg *config);

static const int      default_back_log   = 10;
static const uint16_t default_mtu        = 1500;
static const uint16_t default_bind_port  = 55555;
static const uint16_t default_max_conn   = 10;
static char           default_dev_name[] = "teavpn10";

/**
 * Return false if parse fails.
 */
bool
tvpn_server_argv_parse(int argc, char *argv[], char *envp[],
                       server_cfg *config)
{
  (void)envp;

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
inline static void
set_default_config(server_cfg *config)
{
  config->config_file = NULL;
  config->data_dir    = NULL;

  /* Virtual network interface. */
  config->iface.dev          = default_dev_name;
  config->iface.ipv4         = NULL;
  config->iface.ipv4_netmask  = NULL;
  config->iface.mtu          = default_mtu;

  /* Socket. */
  config->sock.bind_addr  = NULL;
  config->sock.backlog    = default_back_log;
  config->sock.bind_port  = default_bind_port;
  config->sock.type       = SOCK_TCP;
  config->sock.max_conn   = default_max_conn;
}

static const struct option long_options[] = {

  {"help",          no_argument      , 0, 'h'},
  {"config",        required_argument, 0, 'c'},

  /* Interface options. */
  {"dev",           required_argument, 0, 'd'},
  {"mtu",           required_argument, 0, 'm'},
  {"ipv4",          required_argument, 0, '4'},
  {"ipv4-netmask",  required_argument, 0, 'b'},

  /* Socket options. */
  {"bind-addr",     required_argument, 0, 'H'},
  {"bind-port",     required_argument, 0, 'P'},
  {"sock-type",     required_argument, 0, 's'},
  {"backlog",       required_argument, 0, 'B'},
  {"max-conn",      required_argument, 0, 'M'},

  {"data-dir",      required_argument, 0, 'D'},

  {0, 0, 0, 0}
};

/**
 * Parse the arguments and plug it to config.
 */
inline static bool
getopt_handler(int argc, char **argv, server_cfg *config)
{
  int c;

  #if ARGV_DEBUG
  printf("Parsing arguments...\n");
  #endif

  while (1) {
    int option_index = 0;
    /*int this_option_optind = optind ? optind : 1;*/
    c = getopt_long(argc, argv, "c:hd:m:4:b:H:P:s:B:D:M:", long_options,
                    &option_index);

    if (c == -1)
      break;

    switch (c) {

      case 'h':
        show_help(argv[0]);
        return false;
        break;
      case 'c':
        config->config_file = optarg;
        PRINT_CONFIG(config->config_file, "\"%s\"", optarg);
        break;

      /* [Config options] */
      /* Virtual network interface: */
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
        config->iface.ipv4_netmask = optarg;
        PRINT_CONFIG(config->iface.ipv4_netmask, "\"%s\"", optarg);
        break;

      /* Socket. */
      case 'H':
        config->sock.bind_addr = optarg;
        PRINT_CONFIG(config->sock.bind_addr, "\"%s\"", optarg);
        break;
      case 'P':
        config->sock.bind_port = (uint16_t)atoi(optarg);
        PRINT_CONFIG(config->sock.bind_port, "%d", config->sock.bind_port);
        break;
      case 's': {
        register char tc;
        char targ[4];

        strncpy(targ, optarg, 3);

        tc       = targ[0];
        targ[0] += ('A' <= tc && tc <= 'Z') ? 32 : 0;

        tc       = targ[1];
        targ[1] += ('A' <= tc && tc <= 'Z') ? 32 : 0;

        tc       = targ[2];
        targ[2] += ('A' <= tc && tc <= 'Z') ? 32 : 0;

        targ[3] = '\0';

        if (!strcmp(targ, "tcp")) {
          config->sock.type = SOCK_TCP;
        } else
        if (!strcmp(targ, "udp")) {
          config->sock.type = SOCK_UDP;
        } else {
          printf("Invalid socket type: \"%s\"\n", optarg);
          return false;
        }

        PRINT_CONFIG(
          config->sock.type,
          "%s",
          (config->sock.type == SOCK_TCP) ? "tcp" : "udp"
        );
      }
        break;
      case 'B':
        config->sock.backlog = atoi(optarg);
        PRINT_CONFIG(config->sock.backlog, "%d", config->sock.backlog);
        break;
      case 'M':
        config->sock.max_conn = (uint16_t)atoi(optarg);
        PRINT_CONFIG(config->sock.max_conn, "%d", config->sock.max_conn);
        break;


      case 'D':
        config->data_dir = optarg;
        break;

      case '?':
      default:
        return false;
        break;
    }
  }

  return true;
}

inline static void
show_help(char *app)
{
  printf("Usage: %s [options]\n", app);

  printf("\n");
  printf("TeaVPN2 (An open source VPN software).\n");

  printf("\n");
  printf("Available options:\n");
  printf("  -h, --help\t\t\tShow this help message.\n");
  printf("  -c, --config=FILE\t\tSet config file.\n");

  printf("\n");
  printf("[Config options]\n");
  printf("Virtual network interface:\n");
  printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
         " (default: %s).\n", default_dev_name);
  printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n", default_mtu);
  printf("  -4, --ipv4=IP\t\t\tSet IPv4.\n");
  printf("  -b, --ipv4-netmask=MASK\tSet IPv4 netmask.\n");

  printf("\n");
  printf("Socket:\n");
  printf("  -H, --bind-addr=IP\t\tSet bind address.\n");
  printf("  -P, --bind-port=PORT\t\tSet bind port (default: %d).\n",
         default_bind_port);
  printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
         " (default: tcp).\n");
  printf("  -B, --backlog=TYPE\t\tSet socket listen backlog (default: %d).\n",
         default_back_log);
  printf("  -M, --max-conn=N\t\tSet max connections (default: %d).\n",
         default_max_conn);

  printf("\n");
  printf("Other:\n");
  printf("  -D, --data-dir\t\tSet data directory.\n");

  printf("\n");
  printf("\n");
  printf("For bug reporting, please open an issue on GitHub repository.\n");
  printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
  printf("\n");
  printf("This software is licensed under the MIT license.\n");
}

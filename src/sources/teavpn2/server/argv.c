

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#include <unistd.h>
#include <getopt.h>
#endif

#include <teavpn2/server/argv.h>
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


static bool                no_exec             = false;
static char                default_dev_name[]  = "teavpn10";
static const int           default_back_log    = 10;
static const uint16_t      default_mtu         = 1500;
static const uint16_t      default_bind_port   = 55555;
static const uint16_t      default_max_conn    = 10;


inline static void
set_default_cfg(srv_cfg *cfg);

inline static bool
getopt_handler(int argc, char *argv[], srv_cfg *cfg);


/**
 * @param int     argc
 * @param char    *argv[]
 * @param srv_cfg *cfg
 * @return bool
 */
bool
tvpn_server_argv_parse(int argc, char *argv[], srv_cfg *cfg)
{

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }

  set_default_cfg(cfg);

  if (!getopt_handler(argc, argv, cfg)) {

    return false;
  }

  return !no_exec;
}


/**
 * Initialize default config values.
 *
 * @param server_c
 */
inline static void
set_default_cfg(srv_cfg *cfg)
{
  cfg->config_file = NULL;
  cfg->data_dir    = NULL;

  /* Virtual network interface. */
  cfg->iface.dev          = default_dev_name;
  cfg->iface.ipv4         = NULL;
  cfg->iface.ipv4_netmask = NULL;
  cfg->iface.mtu          = default_mtu;

  /* Socket. */
  cfg->sock.bind_addr  = NULL;
  cfg->sock.backlog    = default_back_log;
  cfg->sock.bind_port  = default_bind_port;
  cfg->sock.type       = SOCK_TCP;
  cfg->sock.max_conn   = default_max_conn;
}


static const char          short_options[]     = \
  "hvc:D:d:m:4:n:H:P:S:B:M:";

static const struct option long_options[]      = {

  {"help",          no_argument,        0,  'h'},
  {"version",       no_argument,        0,  'v'},
  {"config",        required_argument,  0,  'c'},
  {"data-dir",      required_argument,  0,  'D'},

  /*  Interface options. */
  {"dev",           required_argument,  0,  'd'},
  {"mtu",           required_argument,  0,  'm'},
  {"ipv4",          required_argument,  0,  '4'},
  {"ipv4-netmask",  required_argument,  0,  'n'},

  /*  Socket options. */
  {"bind-addr",     required_argument,  0,  'H'},
  {"bind-port",     required_argument,  0,  'P'},
  {"sock-type",     required_argument,  0,  'S'},
  {"backlog",       required_argument,  0,  'B'},
  {"max-conn",      required_argument,  0,  'M'},

  {0,               0,                  0,   0 }
};


/**
 * @param int     argc
 * @param char    *argv[]
 * @param srv_cfg *cfg
 * @return bool
 */
inline static bool
getopt_handler(int argc, char *argv[], srv_cfg *cfg)
{
  int c;

  while (true) {

    int option_index = 0;
    /*int this_option_optind = optind ? optind : 1;*/

    c = getopt_long(argc, argv, short_options,
                    long_options, &option_index);

    if (c == -1) {
      break;
    }

    // "hvc:D:d:m:4:n:H:P:S:B:M:"

    switch (c) {
      case 'v':
        no_exec = true;
        goto ret;
        break;

      case 'h':
        no_exec = true;
        goto ret;
        break;

      case 'c':
        cfg->config_file = optarg;
        PRINT_CONFIG(cfg->config_file, "\"%s\"", optarg);
        break;


      /* Virtual network interface configuration. */
      case 'd':
        cfg->iface.dev = optarg;
        PRINT_CONFIG(cfg->iface.dev, "\"%s\"", optarg);
        break;

      case 'm':
        cfg->iface.mtu = (uint16_t)atoi(optarg);
        PRINT_CONFIG(cfg->iface.mtu, "%d", cfg->iface.mtu);
        break;

      case '4':
        cfg->iface.ipv4 = optarg;
        PRINT_CONFIG(cfg->iface.ipv4, "\"%s\"", optarg);
        break;

      case 'n':
        cfg->iface.ipv4_netmask = optarg;
        PRINT_CONFIG(cfg->iface.ipv4_netmask, "\"%s\"", optarg);
        break;


      /* Socket configuration. */
      case 'H':
        cfg->sock.bind_addr = optarg;
        PRINT_CONFIG(cfg->sock.bind_addr, "\"%s\"", optarg);
        break;

      case 'P':
        cfg->sock.bind_port = (uint16_t)atoi(optarg);
        PRINT_CONFIG(cfg->sock.bind_port, "%d", cfg->sock.bind_port);
        break;

      case 'S': {
        char     targ[4];
        uint32_t *targ_ptr = (uint32_t *)targ;

        strncpy(targ, optarg, 3);

        /* tolower */
        *targ_ptr = (*targ_ptr) | 0x20202020;
        targ[3]   = '\0';

        if (!strcmp(targ, "tcp")) {
          cfg->sock.type = SOCK_TCP;
        } else
        if (!strcmp(targ, "udp")) {
          cfg->sock.type = SOCK_UDP;
        } else {
          debug_log(0, "Invalid socket type: \"%s\"\n", optarg);
          return false;
        }
      } break;

      case 'B':
        cfg->sock.backlog = atoi(optarg);
        PRINT_CONFIG(cfg->sock.backlog, "%d", cfg->sock.backlog);
        break;

      case 'M':
        cfg->sock.max_conn = (uint16_t)atoi(optarg);
        PRINT_CONFIG(cfg->sock.max_conn, "%d", cfg->sock.max_conn);
        break;

      case '?':
      default:
        return false;
    }
  }

ret:
  return true;
}

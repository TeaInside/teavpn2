
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#  include <unistd.h>
#  include <getopt.h>
#endif

#include <teavpn2/server/argv.h>


/* Default socket configuration. */
static char     def_bind_addr[]    = "0.0.0.0";
static uint16_t def_bind_port      = 55555;
static uint16_t def_max_conn       = 10;
static int      def_backlog        = 10;

/* Default virtual network interface configuration. */
static char     def_dev[]          = "teavpn2";
static char     def_ipv4[]         = "10.10.10.1";
static char     def_ipv4_netmask[] = "255.255.255.0";
static uint16_t def_mtu            = 1500;

/* Cancellation state. */
static bool     no_exec            = false;


/**
 * @param srv_cfg *cfg
 * @return void
 */
inline static void
set_default_cfg(srv_cfg *cfg)
{
  cfg->cfg_file       = NULL;
  cfg->data_dir       = NULL;

  cfg->sock.type      = SOCK_TCP;
  cfg->sock.bind_addr = def_bind_addr;
  cfg->sock.bind_port = def_bind_port;
  cfg->sock.max_conn  = def_max_conn;
  cfg->sock.backlog   = def_backlog;

  cfg->iface.dev          = def_dev;
  cfg->iface.ipv4         = def_ipv4;
  cfg->iface.ipv4_netmask = def_ipv4_netmask;
  cfg->iface.mtu          = def_mtu;
}


static const char short_opt[2] = "";
static const struct option long_opt[2] = {};

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

    c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case 'v':
        no_exec = true;
        goto ret;

      case 'h':
        no_exec = true;
        goto ret;

      case 'c':
        cfg->cfg_file = optarg;
        break;


      /* Virtual network interface configuration. */
      case 'd':
        cfg->iface.dev = optarg;
        break;

      case '4':
        cfg->iface.ipv4 = optarg;
        break;

      case 'n':
        cfg->iface.ipv4_netmask = optarg;
        break;

      case 'm':
        cfg->iface.mtu = (uint16_t)atoi(optarg);
        break;


      /* Socket configuration. */
      case 'S': {
        char     targ[4] = {0, 0, 0, 0};
        uint32_t *ptr    = (uint32_t *)targ;

        strncpy(targ, optarg, 3);

        /* strtolower */
        *ptr    |= 0x20202020;
        targ[3]  = '\0';

        if (!strcmp(targ, "tcp")) {
          cfg->sock.type = SOCK_TCP;
        } else
        if (!strcmp(targ, "udp")) {
          cfg->sock.type = SOCK_UDP;
        } else {
          err_printf("Invalid socket type \"%s\"", optarg);
          return false;
        }
      } break;

      case 'H':
        cfg->sock.bind_addr = optarg;
        break;

      case 'P':
        cfg->sock.bind_port = (uint16_t)atoi(optarg);
        break;

      case 'M':
        cfg->sock.max_conn = (uint16_t)atoi(optarg);
        break;

      case 'B':
        cfg->sock.backlog = atoi(optarg);
        break;


      case '?':
      default:
        return false;
    }
  }


ret:
  return true;
}


/**
 * @param int     argc
 * @param char    *argv[]
 * @param srv_cfg *cfg
 * @return bool
 */
bool
tsrv_argv_parser(int argc, char *argv[], srv_cfg *cfg)
{
  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }

  set_default_cfg(cfg);

  if (!getopt_handler(argc, argv, cfg)) {
    no_exec = true;
  }

  print_cfg(cfg);

  return (!no_exec);
}


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#  include <unistd.h>
#  include <getopt.h>
#endif

#include <inih/ini.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/helpers.h>

#include <teavpn2/server/common.h>

struct parse_struct {
  bool      no_exec;
  srv_cfg   *cfg;
};

extern const char *app_name;

/* Default socket configuration. */
static char     def_bind_addr[]    = "0.0.0.0";
static uint16_t def_bind_port      = 55555;
static uint16_t def_max_conn       = 10;
static int      def_backlog        = 10;

/* Default virtual network interface configuration. */
static char     def_dev[]          = "teavpn2";
static char     def_ipv4[]         = "10.50.50.1";
static char     def_ipv4_netmask[] = "255.255.255.0";
static uint16_t def_mtu            = 1500;

/* Default configuration file. */
static char     def_cfg_file[]     = "config/server.ini";


/**
 * @param srv_cfg *cfg
 * @return void
 */
static inline void
set_default_cfg(srv_cfg *cfg)
{
  cfg->cfg_file       = def_cfg_file;
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


static const char short_opt[] = "hvc:D:d:4:b:m:s:H:P:M:B:";
static const struct option long_opt[] = {
  {"help",          no_argument,       0, 'h'},
  {"version",       no_argument,       0, 'v'},
  {"config",        required_argument, 0, 'c'},
  {"data-dir",      required_argument, 0, 'D'},

  /* Virtual network interface options. */
  {"dev",           required_argument, 0, 'd'},
  {"ipv4",          required_argument, 0, '4'},
  {"ipv4-netmask",  required_argument, 0, 'b'},
  {"mtu",           required_argument, 0, 'm'},

  /* Socket options. */
  {"sock-type",     required_argument, 0, 's'},
  {"bind-addr",     required_argument, 0, 'H'},
  {"bind-port",     required_argument, 0, 'P'},
  {"max-conn",      required_argument, 0, 'M'},
  {"backlog",       required_argument, 0, 'B'},

  {0, 0, 0, 0}
};

static inline void
show_help(const char *app);


/**
 * @param int                 argc
 * @param char                *argv[]
 * @param struct parse_struct *cx
 * @return bool
 */
static inline bool
getopt_handler(int argc, char *argv[], struct parse_struct *cx)
{
  int c;
  srv_cfg *cfg = cx->cfg;

  while (true) {

    int option_index = 0;
    /*int this_option_optind = optind ? optind : 1;*/

    c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

    if (unlikely(c == -1)) {
      break;
    }

    switch (c) {
      case 'v':
        cx->no_exec = true;
        goto ret;

      case 'h':
        show_help(argv[0]);
        cx->no_exec = true;
        goto ret;

      case 'c':
        cfg->cfg_file = optarg;
        break;

      case 'D':
        cfg->data_dir = optarg;
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
      case 's': {
        char     targ[4] = {0, 0, 0, 0};
        uint32_t *ptr    = (uint32_t *)targ;

        strncpy(targ, optarg, 3);

        /* strtolower */
        *ptr    |= 0x20202020;
        targ[3]  = '\0';

        if (!memcmp(targ, "tcp", 4)) {
          cfg->sock.type = SOCK_TCP;
        } else
        if (!memcmp(targ, "udp", 4)) {
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
  struct parse_struct cx;

  set_default_cfg(cfg);

  if (argc == 1) {
    return true;
  }

  cx.cfg     = cfg;
  cx.no_exec = false;

  if (!getopt_handler(argc, argv, &cx)) {
    cx.no_exec = true;
  }

  return (!cx.no_exec);
}


static inline int
parser_handler(void *user, const char *section, const char *name,
               const char *value, int lineno);


/**
 * @param const char *cfg_file
 * @param srv_cfg    *cfg 
 * @return bool
 */
bool
tsrv_cfg_load(const char *cfg_file, srv_cfg *cfg)
{
  int                 ret;
  struct parse_struct cx;
  
  cx.cfg     = cfg;
  cx.no_exec = false;
  ret        = ini_parse(cfg_file, parser_handler, &cx);

  if (ret < 0) {
    err_printf("File \"%s\" does not exist", cfg_file);
    return false;
  }

  if (cx.no_exec) {
    err_printf("Error loading config file!");
    return false;
  }

  return true;
}


/**
 * @param void       *user
 * @param const char *section
 * @param const char *name
 * @param const char *value
 * @param int        lineno
 * @return int
 */
static inline int
parser_handler(void *user, const char *section, const char *name,
               const char *value, int lineno)
{
  struct parse_struct *cx  = (struct parse_struct *)user;
  srv_cfg             *cfg = cx->cfg;

  #define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))
  #define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))

  RMATCH_S("iface") {

    RMATCH_N("dev") {
      cfg->iface.dev  = ar_strndup(value, 255);
    } else
    RMATCH_N("ipv4") {
      cfg->iface.ipv4 = ar_strndup(value, IPV4L);
    } else
    RMATCH_N("ipv4_netmask") {
      cfg->iface.ipv4_netmask = ar_strndup(value, IPV4L);
    } else
    RMATCH_N("mtu") {
      cfg->iface.mtu = (uint16_t)atoi(value);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("socket") {

    RMATCH_N("sock_type") {
      char     targ[4] = {0, 0, 0, 0};
      uint32_t *ptr    = (uint32_t *)targ;

      strncpy(targ, value, 3);

      /* strtolower */
      *ptr    |= 0x20202020;
      targ[3]  = '\0';

      if (!memcmp(targ, "tcp", 4)) {
        cfg->sock.type = SOCK_TCP;
      } else
      if (!memcmp(targ, "udp", 4)) {
        cfg->sock.type = SOCK_UDP;
      } else {
        err_printf("Invalid socket type \"%s\"", value);
        goto err;
      }
    } else
    RMATCH_N("bind_addr") {
      cfg->sock.bind_addr = ar_strndup(value, 255);
    } else
    RMATCH_N("bind_port") {
      cfg->sock.bind_port = (uint16_t)atoi(value);
    } else
    RMATCH_N("backlog") {
      cfg->sock.backlog = atoi(value);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("other") {

    RMATCH_N("data_dir") {
      cfg->data_dir = ar_strndup(value, 255);
    } else {
      goto invalid_name;
    }

  } else {
    err_printf("Invalid section \"%s\" on line %d", section, lineno);
    goto err;
  }

  return true;


invalid_name:
  err_printf("Invalid name \"%s\" in section \"%s\" on line %d",
             name, section, lineno);

err:
  cx->no_exec = true;
  return false;
}


/**
 * @param const char *app
 * @return void
 */
static inline void
show_help(const char *app)
{
  printf("Usage: %s %s [options]\n", app_name, app);

  printf("\n");
  printf("TeaVPN Server Application\n");
  printf("\n");
  printf("Available options:\n");
  printf("  -h, --help\t\t\tShow this help message.\n");
  printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
         def_cfg_file);
  printf("  -v, --version\t\t\tShow program version.\n");
  printf("  -D, --data-dir\t\tSet data directory.\n");

  printf("\n");
  printf("[Config options]\n");
  printf(" Virtual network interface:\n");
  printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
         " (default: %s).\n", def_dev);
  printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n", def_mtu);
  printf("  -4, --ipv4=IP\t\t\tSet IPv4 (default: %s).\n", def_ipv4);
  printf("  -b, --ipv4-netmask=MASK\tSet IPv4 netmask (default: %s).\n",
         def_ipv4_netmask);

  printf("\n");
  printf(" Socket:\n");
  printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
         " (default: tcp).\n");
  printf("  -H, --bind-addr=IP\t\tSet bind address (default 0.0.0.0).\n");
  printf("  -P, --bind-port=PORT\t\tSet bind port (default: %d).\n",
         def_bind_port);
  printf("  -M, --max-conn=N\t\tSet max connections (default: %d).\n",
         def_max_conn);
  printf("  -B, --backlog=TYPE\t\tSet socket listen backlog (default: %d).\n",
         def_backlog);

  printf("\n");
  printf("\n");
  printf("For bug reporting, please open an issue on GitHub repository.\n");
  printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
  printf("\n");
  printf("This software is licensed under the MIT license.\n");
}

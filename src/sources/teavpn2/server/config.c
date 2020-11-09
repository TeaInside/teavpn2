
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

struct parse_struct {
  bool      no_exec;
  srv_cfg   *cfg;
};


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


static const char short_opt[] = "hvc:d:4:b:m:s:H:P:M:B:D:";
static const struct option long_opt[] = {
  {"help",          no_argument,       0, 'h'},
  {"version",       no_argument,       0, 'v'},
  {"config",        required_argument, 0, 'c'},

  /* Interface options. */
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

  {"data-dir",      required_argument, 0, 'D'},

  {0, 0, 0, 0}
};

/**
 * @param int                 argc
 * @param char                *argv[]
 * @param struct parse_struct *cx
 * @return bool
 */
inline static bool
getopt_handler(int argc, char *argv[], struct parse_struct *cx)
{
  int c;
  srv_cfg *cfg = cx->cfg;

  while (true) {

    int option_index = 0;
    /*int this_option_optind = optind ? optind : 1;*/

    c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

    if (c == -1) {
      break;
    }

    switch (c) {
      case 'v':
        cx->no_exec = true;
        goto ret;

      case 'h':
        cx->no_exec = true;
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

  cx.cfg  = cfg;
  cx.no_exec = false;

  if (argc == 1) {
    printf("Usage: %s [options]\n", argv[0]);
    return false;
  }

  set_default_cfg(cfg);

  if (!getopt_handler(argc, argv, &cx)) {
    cx.no_exec = true;
  }

  print_cfg(cfg);

  return (!cx.no_exec);
}


inline static int
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
  
  cx.cfg  = cfg;
  cx.no_exec = false;

  ret = ini_parse(cfg_file, parser_handler, &cx);

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
inline static int
parser_handler(void *user, const char *section, const char *name,
               const char *value, int lineno)
{
  struct parse_struct *cx  = (struct parse_struct *)user;
  srv_cfg             *cfg = cx->cfg;

  #define RMATCH_S(STR) if (unlikely(!strcmp(section, STR)))
  #define RMATCH_N(STR) if (unlikely(!strcmp(name, STR)))

  #define RMATCH_S(STR) if (unlikely(!strcmp(section, STR)))
  #define RMATCH_N(STR) if (unlikely(!strcmp(name, STR)))

  RMATCH_S("iface") {

    RMATCH_N("dev") {
      cfg->iface.dev  = ar_strndup(value, 255);
    } else
    RMATCH_N("ipv4") {
      cfg->iface.ipv4 = ar_strndup(value, IPV4L);
    } else
    RMATCH_N("ipv4_netmask") {
      cfg->iface.ipv4_netmask = ar_strndup(value, IPV4L);
    }
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
  } else {
    err_printf("Invalid section \"%s\" on line %d", section, lineno);
    goto err;
  }

  return true;


invalid_name:
  err_printf("Invalid name: \"%s\" in section \"%s\" on line %d\n",
             name, section, lineno);

err:
  cx->no_exec = true;
  return false;
}

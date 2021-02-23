
#include <string.h>
#include <stdlib.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>


static inline int
parser_handler(void *user, const char *section, const char *name,
               const char *value, int lineno);

struct parse_struct {
  bool      fail;
  srv_cfg   *cfg;
};


/**
 * @param char    *file
 * @param srv_cfg *cfg
 * @return bool
 */
bool
tvpn_srv_load_cfg_file(char *file, srv_cfg *cfg)
{
  int                 ret;
  struct parse_struct cx;
  
  cx.cfg  = cfg;
  cx.fail = false;

  ret = ini_parse(file, parser_handler, &cx);

  if (ret < 0) {
    debug_log(0, "File \"%s\" does not exist", file);
    return false;
  }

  if (cx.fail) {
    debug_log(0, "Error loading config file!");
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

  #define RMATCH_S(STR) if (!strcmp(section, STR))
  #define RMATCH_N(STR) if (!strcmp(name, STR))

  #define RMATCH_S(STR) if (!strcmp(section, STR))
  #define RMATCH_N(STR) if (!strcmp(name, STR))

  RMATCH_S("iface") {

    RMATCH_N("dev") {
      cfg->iface.dev  = t_ar_strndup(value, 256);
    } else
    RMATCH_N("mtu") {
      cfg->iface.mtu = (uint16_t)atoi(value);
    } else
    RMATCH_N("ipv4") {
      cfg->iface.ipv4 = t_ar_alloc(IPV4L + 3);
      strncpy(cfg->iface.ipv4, value, IPV4L + 2);
    } else
    RMATCH_N("ipv4_netmask") {
      cfg->iface.ipv4_netmask = t_ar_strndup(value, IPV4L - 1);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("socket") {

    RMATCH_N("bind_addr") {
      cfg->sock.bind_addr = t_ar_strndup(value, 256);
    } else
    RMATCH_N("bind_port") {
      cfg->sock.bind_port = (uint16_t)atoi(value);
    } else
    RMATCH_N("sock_type") {
      char     targ[4];
      uint32_t *targ_ptr = (uint32_t *)targ;

      strncpy(targ, value, 3);

      /* tolower */
      *targ_ptr = (*targ_ptr) | 0x20202020;
      targ[3]   = '\0';

      if (!strcmp(targ, "tcp")) {
        cfg->sock.type = SOCK_TCP;
      } else
      if (!strcmp(targ, "udp")) {
        cfg->sock.type = SOCK_UDP;
      } else {
        debug_log(0, "Invalid socket type: \"%s\"\n", value);
        return 0;
      }

    } else
    RMATCH_N("backlog") {
      cfg->sock.backlog = atoi(value);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("other") {
    cfg->data_dir = t_ar_strndup(value, 256);
  } else {
    debug_log(0, "Invalid section \"%s\" on line %d\n",
              section, lineno);
    cx->fail = true;
    return 0;
  }

  return 1;


invalid_name:
  debug_log(0,
            "Invalid name: \"%s\" in section \"%s\" on line %d\n",
            name, section, lineno);

  cx->fail = true;
  return 0;
}

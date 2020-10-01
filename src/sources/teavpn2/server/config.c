
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>


inline static int server_parser_handler(
  void *user,
  const char *section,
  const char *name,
  const char *value,
  int lineno
);


bool tvpn_server_load_config_file(char *file, server_cfg *config)
{
  return ini_parse(file, server_parser_handler, config) >= 0;
}


inline static int server_parser_handler(
  void *user,
  const char *section,
  const char *name,
  const char *value,
  int lineno
)
{
  server_cfg *config = (server_cfg *)user;

  #define RMATCH_S(STR) if (!strcmp(section, STR))
  #define RMATCH_N(STR) if (!strcmp(name, STR))

  RMATCH_S("iface") {

    RMATCH_N("dev") {
      config->iface.dev  = t_ar_strndup(value, 256);
    } else
    RMATCH_N("mtu") {
      config->iface.mtu = (uint16_t)atoi(value);
    } else
    RMATCH_N("ipv4") {
      config->iface.ipv4 = t_ar_strndup(value, sizeof("xxx.xxx.xxx.xxx") - 1);
    } else
    RMATCH_N("ipv4_bcmask") {
      config->iface.ipv4_bcmask = t_ar_strndup(value, sizeof("xxx.xxx.xxx.xxx") - 1);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("socket") {

    RMATCH_N("bind_addr") {
      config->sock.bind_addr = t_ar_strndup(value, 256);
    } else
    RMATCH_N("bind_port") {
      config->sock.bind_port = (uint16_t)atoi(value);
    } else
    RMATCH_N("sock_type") {
      char targ[4];

      strncpy(targ, value, 3);
      targ[0] = (targ[0] >= 'A' && targ[0] <= 'Z') ? targ[0] + 32 : targ[0];
      targ[1] = (targ[1] >= 'A' && targ[1] <= 'Z') ? targ[1] + 32 : targ[1];
      targ[2] = (targ[2] >= 'A' && targ[2] <= 'Z') ? targ[2] + 32 : targ[2];
      targ[3] = '\0';

      if (!strcmp(targ, "tcp")) {
        config->sock.type = sock_tcp;
      } else
      if (!strcmp(targ, "udp")) {
        config->sock.type = sock_udp;
      } else {
        printf("Invalid socket type: \"%s\"\n", value);
        return 0;
      }

    } else
    RMATCH_N("backlog") {
      config->sock.backlog = atoi(value);
    } else {
      goto invalid_name;
    }

  } else
  RMATCH_S("other") {
    config->data_dir = t_ar_strndup(value, 256);
  } else {
    printf("Invalid section \"%s\" on line %d\n", section, lineno);
    return 0;
  }

  return 1;
invalid_name:
  printf("Invalid name: \"%s\" in section \"%s\" on line %d\n", name, section, lineno);
  return 0;
}

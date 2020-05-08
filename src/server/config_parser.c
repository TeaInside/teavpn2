
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/config_parser.h>

static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno);

bool teavpn_server_config_parser(char *ini_file, teavpn_server_config *config)
{
  int ret = ini_parse(ini_file, parser_handler, config);

  if (ret < 0) {
    printf("Can't load %s\n", ini_file);
    return false;
  }

  return (ret == 0);
}

static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno)
{
  teavpn_server_config *config = (teavpn_server_config *)user;

  #define CMP(A, B) (!strcmp(A, B))
  #define RMATCH(A) if (CMP(A, name))

  if (CMP(section, "iface")) {
    RMATCH("dev") {
      config->iface.dev = arena_strdup(value);
      return 1;
    } else
    RMATCH("mtu") {
      config->iface.mtu = (uint16_t)atoi((char *)value);
      return 1;
    } else
    RMATCH("inet4") {
      config->iface.inet4 = arena_strdup(value);
      return 1;
    } else
    RMATCH("inet4_bcmask") {
      config->iface.inet4_bcmask = arena_strdup(value);
      return 1;
    } else {
      goto invalid_opt;
    }
  } else
  if (CMP(section, "socket")) {
    RMATCH("type") {
      if (CMP(value, "tcp")) {
        config->socket_type = teavpn_sock_tcp;
      } else if (CMP(value, "udp")) {
        config->socket_type = teavpn_sock_udp;
      } else {
        printf("Invalid socket type: \"%s\" on line %d\n", value, lineno);
        return 0;
      }
    } else
    RMATCH("bind_addr"){
      config->socket.bind_addr = arena_strdup(value);
    } else
    RMATCH("bind_port") {
      config->socket.bind_port = (uint16_t)atoi(value);
    } else {
      goto invalid_opt;
    }
  }

  return 1;
invalid_opt:
  printf("Invalid config name \"%s\" on line %d\n", name, lineno);
  return 0;
}

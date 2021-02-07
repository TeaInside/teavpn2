
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <inih/ini.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/config_parser.h>

static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno);

/**
 * @param char *ini_file
 * @param teavpn_client_config *config
 * @return bool
 */
bool teavpn_client_config_parser(char *ini_file, teavpn_client_config *config)
{
  int ret = ini_parse(ini_file, parser_handler, config);

  if (ret < 0) {
    printf("Can't load %s\n", ini_file);
    return false;
  }

  return (ret == 0);
}

/**
 * @param void *user
 * @param const char *section
 * @param const char *name
 * @param const char *value
 * @param int lineno
 * @return int
 */
static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno)
{
  teavpn_client_config *config = (teavpn_client_config *)user;

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
    RMATCH("server_addr"){
      config->socket.server_addr = arena_strdup(value);
    } else
    RMATCH("server_port") {
      config->socket.server_port = (uint16_t)atoi(value);
    } else {
      goto invalid_opt;
    }
  } else
  if (CMP(section, "auth")) {
    RMATCH("username") {
      config->auth.username = arena_strdup(value);
    } else
    RMATCH("password") {
      config->auth.password = arena_strdup(value);
    } else {
      goto invalid_opt;
    }
  }

  return 1;
invalid_opt:
  printf("Invalid config name \"%s\" on line %d\n", name, lineno);
  return 0;
}

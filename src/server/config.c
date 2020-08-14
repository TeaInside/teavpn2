
#include <string.h>
#include <inih/ini.h>
#include <teavpn/server/common.h>

static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno);

/**
 * @param char *ini_file
 * @param server_config *config
 * @return bool
 */
bool teavpn_server_config_parser(char *ini_file, server_config *config)
{
  int ret = ini_parse(ini_file, parser_handler, config);

  if (ret < 0) {
    printf("Can't load %s\n", ini_file);
    return false;
  }

  return (ret == 0);
}

/**
 * @param void        *user
 * @param const char  *section
 * @param const char  *name
 * @param const char  *value
 * @param int         lineno
 * @return int
 */
static int parser_handler(void *user, const char *section, const char *name, const char *value, int lineno)
{
  server_config *config = (server_config *)user;

  #define CMP(A, B) (!strcmp(A, B))
  #define RMATCH(A) if (CMP(A, name))

  if (CMP(section, "iface")) {
    RMATCH("dev") {
      config->net.dev = stack_strdup(value);
      return 1;
    } else
    RMATCH("mtu") {
      config->net.mtu = (uint16_t)atoi((char *)value);
      return 1;
    } else
    RMATCH("inet4") {
      config->net.inet4 = stack_strdup(value);
      return 1;
    } else
    RMATCH("inet4_bcmask") {
      config->net.inet4_bcmask = stack_strdup(value);
      return 1;
    } else {
      goto invalid_opt;
    }
  } else
  if (CMP(section, "socket")) {
    RMATCH("type") {
      if (CMP(value, "tcp")) {
        config->sock_type = TEAVPN_SOCK_TCP;
      } else if (CMP(value, "udp")) {
        config->sock_type = TEAVPN_SOCK_UDP;
      } else {
        printf("Invalid socket type: \"%s\" on line %d\n", value, lineno);
        return 0;
      }
    } else
    RMATCH("bind_addr") {
      config->bind_addr = stack_strdup(value);
    } else
    RMATCH("bind_port") {
      config->bind_port = (uint16_t)atoi(value);
    } else
    RMATCH("backlog") {
      config->backlog = (int)atoi(value);
    } else {
      goto invalid_opt;
    }
  } else
  if (CMP(section, "data")) {
    RMATCH("data_dir") {
      config->data_dir = stack_strdup(value);
    }
  }

  return 1;
invalid_opt:
  printf("Invalid config name \"%s\" on line %d\n", name, lineno);
  return 0;
}

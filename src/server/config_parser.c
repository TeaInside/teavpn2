
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <inih/ini.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/config_parser.h>

static int parser_handler();

bool teavpn_server_config_parser(char *ini_file, teavpn_server_config *config)
{
  if (ini_parse(ini_file, parser_handler, &config) < 0) {
    printf("Can't load %s\n", ini_file);
    return 1;
  }
}

static int parser_handler(void *user, const char *section, const char *name, const char *value)
{
  teavpn_server_config *config = (teavpn_server_config *)user;

  #define CMP(A, B) (!strcmp(A, B))
  #define RMATCH(NAME) \
    if (CMP(name, NAME))

  if (CMP(section, "iface")) {
    RMATCH("dev") {
      config->iface.dev = (char *)value;
    } else
    RMATCH("mtu") {
      config->iface.mtu = atoi((char *)value);
    } else
    RMATCH("inet4") {
      config->iface.inet4 = (char *)value;
    } else
    RMATCH("inet4_bcmask") {
      config->iface.inet4_bcmask = (char *)value;
    }
  } else
  if (CMP(section, "socket")) {
    RMATCH("type") {
      if (CMP(value, "tcp")) {
        
      }
    }
  }

  #undef MATCH
}

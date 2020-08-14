
#ifndef TEAVPN__SERVER__COMMON_H
#define TEAVPN__SERVER__COMMON_H

#include <teavpn/global/common.h>

typedef struct _server_argv {
  char        *config_file;
  char        *bind_addr;
  uint16_t    bind_port;
} server_arg;

bool teavpn_server_arg_parser(int argc, char **argv, char *envp, server_arg *arg);

#endif

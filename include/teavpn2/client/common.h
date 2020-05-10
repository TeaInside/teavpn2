
#ifndef TEAVPN__SERVER__COMMON_H
#define TEAVPN__SERVER__COMMON_H

#include <stdbool.h>

#include <teavpn2/global/common.h>

#include <teavpn2/client/config.h>
#include <teavpn2/client/debugger.h>
#include <teavpn2/client/config_parser.h>

bool teavpn_server_argv_parser(int argc, char **argv, char **envp, teavpn_client_config *config);
int teavpn_server_run(teavpn_client_config *config);

#endif

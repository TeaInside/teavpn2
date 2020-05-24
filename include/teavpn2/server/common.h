
#ifndef __TEAVPN__SERVER__COMMON_H
#define __TEAVPN__SERVER__COMMON_H

#include <teavpn/global/auth.h>

#include <teavpn/server/config.h>

int teavpn_server_run(teavpn_server_config *config);
bool teavpn_server_argv_parser(int argc, char **argv, char **envp, teavpn_server_config *config);


#endif

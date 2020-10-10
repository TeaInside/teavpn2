
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/global/common.h>
#include <teavpn2/global/types.h>
#include <teavpn2/server/config.h>

bool
tvpn_server_argv_parse(int argc, char *argv[], char *envp[],
                       server_cfg *config);

bool
tvpn_server_load_config_file(char *file, server_cfg *config);

int
tvpn_server_run(server_cfg *config);

bool
server_tun_iface_up(server_iface_cfg *iface);

#endif

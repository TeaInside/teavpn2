
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <teavpn2/global/common.h>
#include <teavpn2/global/types.h>
#include <teavpn2/server/config.h>

int
tvpn_server_run(server_cfg *config);

bool
server_tun_iface_up(server_iface_cfg *iface);

void 
tvpn_server_version_info();

#endif

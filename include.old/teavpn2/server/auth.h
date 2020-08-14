
#ifndef TEAVPN__SERVER__AUTH_H
#define TEAVPN__SERVER__AUTH_H

#include <stdbool.h>
#include <teavpn2/server/config.h>
#include <teavpn2/server/data_struct.h>

bool teavpn_server_auth_handle(
  char *username,
  char *password,
  teavpn_server_config *config,
  teavpn_srv_iface_info *iface_info
);

#endif

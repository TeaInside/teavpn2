
#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/global/common.h>
#include <teavpn2/client/config.h>


/* argv_parser */
bool
tvpn_client_argv_parse(int argc, char *argv[], char *envp[],
                       client_cfg *config);
/* End of argv_parser */


/* config */
bool
tvpn_client_load_config_file(char *file, client_cfg *config);
/* End of config */

int
tvpn_client_run(client_cfg *config);

int
tvpn_client_tcp_run(client_cfg *config);

bool
client_tun_iface_up(client_iface_cfg *iface);

#endif

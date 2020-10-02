
#ifndef TEAVPN2__CLIENT__COMMON_H
#define TEAVPN2__CLIENT__COMMON_H

#include <teavpn2/global/common.h>

typedef struct _client_iface_cfg {
  char                  *dev;           /* Interface name. */
  uint16_t              mtu;            /* MTU. */
} client_iface_cfg;



typedef struct _client_socket_cfg {
  char                  *server_addr;   /* Socket client bind address. */
  uint16_t              server_port;    /* Socket client bind port. */
  socket_type           type;           /* Socket type, TCP/UDP. */
} client_socket_cfg;


typedef struct _client_cfg {

  char                  *config_file;   /* Config file. */
  char                  *data_dir;      /* Data directory. */
  client_iface_cfg      iface;          /* Virtual interface configuration. */
  client_socket_cfg      sock;          /* Socket configuration. */

} client_cfg;



/* argv_parser */
bool tvpn_client_argv_parse(
  int argc,
  char *argv[],
  char *envp[],
  client_cfg *config
);
/* End of argv_parser */


/* config */
bool tvpn_client_load_config_file(char *file, client_cfg *config);
/* End of config */

#endif

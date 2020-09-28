
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <stdbool.h>
#include <teavpn2/global/common.h>

typedef struct _server_iface_cfg {

  char                  *dev;           /* Interface name. */

  char                  *ipv4;          /* IPv4. */
  char                  *ipv4_bcmask;   /* IPv4 broadcast mask. */
  uint16_t              mtu;            /* MTU. */

#if 0
  char                  *ipv6;          /* IPv6. */
  char                  *ipv6_bcmask;   /* IPv6 broadcast mask. */
#endif

} server_iface_cfg;



typedef struct server_config {

  char                  *config_file;   /* Config file. */
  char                  *data_dir;      /* Data directory. */
  server_iface_cfg      iface;          /* Virtual interface configuration. */

} server_config;



/* argv_parser */
bool tvpn_server_argv_parse(
  int argc,
  char *argv[],
  char *envp[],
  server_config *config
);
/* End of argv_parser */

#endif

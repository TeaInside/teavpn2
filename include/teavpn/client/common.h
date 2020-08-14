
#ifndef TEAVPN__CLIENT__COMMON_H
#define TEAVPN__CLIENT__COMMON_H

#include <linux/kernel.h>
#include <teavpn/global/common.h>

typedef struct _client_config {
  char                  *config_file;

  /*
   * Socket communication configuration.
   */
  char                  *server_addr;
  uint16_t              server_port;
  enum socket_type      sock_type;


  /*
   * Authentication.
   */
  char                  *username;
  char                  *password;
} client_config;

typedef struct _client_state {

  int                 iface_fd;

  __be32              inet4;
  __be32              inet4_bcmask;

  client_config       *config;

  /*
   * Virtual network interface configuration.
   */
  teavpn_net            net;

} client_state;

bool teavpn_client_arg_parser(int argc, char **argv, char **envp, client_config *config);
int teavpn_client_run(client_config *config);
int teavpn_client_tcp_run(client_state *config);
int teavpn_client_udp_run(client_state *config);

#endif

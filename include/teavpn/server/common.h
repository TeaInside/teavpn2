
#ifndef TEAVPN__SERVER__COMMON_H
#define TEAVPN__SERVER__COMMON_H

#include <arpa/inet.h>
#include <linux/kernel.h>
#include <teavpn/global/common.h>

typedef struct _server_config {
  char                  *config_file;
  char                  *data_dir;

  /*
   * Socket communication configuration.
   */
  char                  *bind_addr;
  uint16_t              bind_port;
  int                   backlog;
  enum socket_type      sock_type;

  /*
   * Virtual network interface configuration.
   */
  teavpn_net            net;
} server_config;

typedef struct _server_state {

  int                   iface_fd;

  __be32                inet4;
  __be32                inet4_bcmask;

  server_config         *config;

} server_state;

bool teavpn_server_arg_parser(int argc, char **argv, char **envp, server_config *config);
bool teavpn_server_config_parser(char *ini_file, server_config *config);
int teavpn_server_run(server_config *config);
int teavpn_server_tcp_run(server_state *config);
int teavpn_server_udp_run(server_state *config);

#endif

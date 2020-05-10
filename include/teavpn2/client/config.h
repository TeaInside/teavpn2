
#ifndef TEAVPN__CLIENT__CONFIG_H
#define TEAVPN__CLIENT__CONFIG_H

#include <teavpn2/global/config.h>

typedef struct {
  char *config_file;
  char *data_dir;
  struct teavpn_iface iface;
  enum teavpn_socket_type socket_type;
  struct {
    char *server_addr;
    uint16_t server_port;
  } socket;
} teavpn_client_config;

#endif


#ifndef TEAVPN__SERVER__CONFIG_H
#define TEAVPN__SERVER__CONFIG_H

#include <teavpn2/global/config.h>

typedef struct {
  char *config_file;
  char *data_dir;
  struct teavpn_iface iface;
  enum teavpn_socket_type socket_type;
  struct {
    char *bind_addr;
    uint16_t bind_port;
  } socket;
  void *mstate;
} teavpn_server_config;

#endif


#ifndef TEAVPN__SERVER__CONFIG_H
#define TEAVPN__SERVER__CONFIG_H

#include <teavpn2/global/config.h>

struct teavpn_iface {
  char *dev;
  char *inet4;
  char *inet4_bcmask;
  uint16_t mtu;
  char *data_dir;
};

typedef struct {
  char *config_file;
  char *data_dir;
  struct teavpn_iface iface;
  enum teavpn_socket_type socket_type;
  struct {
    char *bind_addr;
    uint16_t bind_port;
  } socket;
} teavpn_server_config;

#endif

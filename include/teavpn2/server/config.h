
#ifndef TEAVPN__SERVER__CONFIG_H
#define TEAVPN__SERVER__CONFIG_H

struct teavpn_iface {
  char *dev;
  char *inet4;
  char *inet4_bcmask;
  uint16_t mtu;
  char *data_dir;
};

struct teavpn_server_tcp {
  char *bind_addr;
  uint16_t bind_port;
  struct teavpn_iface iface;
};

struct teavpn_server_udp {
  char *bind_addr;
  uint16_t bind_port;
  struct teavpn_iface iface;
};

enum teavpn_server_type {
  teavpn_server_tcp_type = (1 << 0),
  teavpn_server_udp_type = (1 << 1)
};

union teavpn_server {
  struct teavpn_server_tcp tcp;
  struct teavpn_server_udp udp;
};

typedef struct {
  enum teavpn_server_type type;
  union teavpn_server server;
} teavpn_server_config;

#endif

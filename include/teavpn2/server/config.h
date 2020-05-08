
#ifndef TEAVPN__SERVER__CONFIG_H
#define TEAVPN__SERVER__CONFIG_H

typedef struct {
  char *tcp_bind_addr;
  uint16_t tcp_bind_port;
} teavpn_server_tcp;

typedef struct {
  char *udp_bind_addr;
  uint16_t udp_bind_port;
} teavpn_server_udp;

enum teavpn_server_type {
  teavpn_server_tcp_type = (1 << 0),
  teavpn_server_udp_type = (1 << 1)
};

union teavpn_server {
  teavpn_server_tcp tcp;
  teavpn_server_udp udp;
};

typedef struct {
  enum teavpn_server_type type;
  union teavpn_server server;
} teavpn_server_config;

#endif

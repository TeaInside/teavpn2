
#ifndef TEAVPN__GLOBAL__CONFIG_H
#define TEAVPN__GLOBAL__CONFIG_H

#include <stdint.h>

struct teavpn_iface {
  char *dev;
  char *inet4;
  char *inet4_bcmask;
  uint16_t mtu;
};

enum teavpn_socket_type {
  teavpn_sock_tcp = (1 << 0),
  teavpn_sock_udp = (1 << 1)
};

#endif

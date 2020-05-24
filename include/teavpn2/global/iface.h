
#ifndef TEAVPN__GLOBAL__IFACE_H
#define TEAVPN__GLOBAL__IFACE_H

#include <stdbool.h>
#include <teavpn2/global/config.h>

typedef struct {
  int tun_fd;
} iface_info;

int teavpn_iface_allocate(char *dev);
bool teavpn_iface_init(struct teavpn_iface *iface);
bool teavpn_iface_clean_up(struct teavpn_iface *iface);

#endif

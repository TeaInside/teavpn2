

#ifndef __TEAVPN2__GLOBAL__HELPERS__LINUX__IFACE_H
#define __TEAVPN2__GLOBAL__HELPERS__LINUX__IFACE_H

#include <stdbool.h>

int tun_alloc(const char *dev, int flags);
int tun_set_queue(int fd, bool enable);

#endif /* #ifndef __TEAVPN2__GLOBAL__HELPERS__LINUX__IFACE_H */

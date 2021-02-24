
#ifndef __TEAVPN2__HELPERS__LINUX__IFACE_H
#define __TEAVPN2__HELPERS__LINUX__IFACE_H

#include <stdbool.h>
#include <teavpn2/global/common.h>

int tun_alloc(const char *dev, int flags);
int tun_set_queue(int fd, bool enable);
int raise_iface(struct iface_cfg *iface);

#endif /* #ifndef __TEAVPN2__HELPERS__LINUX__IFACE_H */

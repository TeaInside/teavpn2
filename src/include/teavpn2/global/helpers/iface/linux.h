
#ifndef TEAVPN2__GLOBAL__HELPERS__IFACE__LINUX_H
#define TEAVPN2__GLOBAL__HELPERS__IFACE__LINUX_H

#include <linux/if_tun.h>

int
tun_alloc(const char *dev, int flags);

int
tun_set_queue(int fd, bool enable);

#endif /* #ifndef TEAVPN2__GLOBAL__HELPERS__IFACE__LINUX_H */

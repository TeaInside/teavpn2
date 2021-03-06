
#ifndef __TEAVPN2__NET__LINUX__IFACE_H
#define __TEAVPN2__NET__LINUX__IFACE_H

#include <stdbool.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <teavpn2/base.h>


int fd_set_nonblock(int fd);
int tun_alloc(const char *dev, int flags);

#endif /* #ifndef __TEAVPN2__NET__LINUX__IFACE_H */

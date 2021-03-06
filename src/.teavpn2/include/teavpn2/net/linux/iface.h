
#ifndef TEAVPN2__NET__LINUX__IFACE_H
#define TEAVPN2__NET__LINUX__IFACE_H

#include <stdbool.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <teavpn2/__base.h>


int tun_alloc(const char *dev, int flags);
int fd_set_nonblock(int fd);
bool raise_up_iface(struct iface_rd_cfg *iface);

#endif /* #ifndef TEAVPN2__NET__LINUX__IFACE_H */

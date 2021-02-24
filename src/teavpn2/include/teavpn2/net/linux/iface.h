
#ifndef __TEAVPN2__NET__LINUX__IFACE_H
#define __TEAVPN2__NET__LINUX__IFACE_H

#include <linux/if.h>
#include <linux/if_tun.h>
#include <teavpn2/__base.h>


int tun_alloc(const char *dev, int flags);
int tun_set_queue(int fd, bool enable);
bool raise_up_interface(struct iface_cfg *iface);
int fd_set_nonblock(int fd);

#endif /* #ifndef __TEAVPN2__NET__LINUX__IFACE_H */

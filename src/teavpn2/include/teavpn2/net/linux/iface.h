// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/net/linux/iface.h
 *
 *  Network interface helper.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__NET__LINUX__IFACE_H
#define TEAVPN2__NET__LINUX__IFACE_H

#include <teavpn2/base.h>
#include <linux/if_tun.h>

int fd_set_nonblock(int fd);
int tun_alloc(const char *dev, short flags);
bool teavpn_iface_up(struct if_info *iface);
bool teavpn_iface_down(struct if_info *iface);

#endif /* #ifndef TEAVPN2__NET__LINUX__IFACE_H */

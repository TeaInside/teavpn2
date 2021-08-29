// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Network interface helper.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__NET__LINUX__IFACE_H
#define TEAVPN2__NET__LINUX__IFACE_H

#include <teavpn2/common.h>
#include <linux/if_tun.h>

extern int fd_set_nonblock(int fd);
extern int tun_alloc(const char *dev, short flags);
extern bool teavpn_iface_up(struct if_info *iface);
extern bool teavpn_iface_down(struct if_info *iface);

#endif /* #ifndef TEAVPN2__NET__LINUX__IFACE_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/include/net/linux/iface.h
 *
 *  Interface header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef TEAVPN2__NET__LINUX__IFACE_H
#define TEAVPN2__NET__LINUX__IFACE_H

#include <stdbool.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <teavpn2/base.h>


int fd_set_nonblock(int fd);
int tun_alloc(const char *dev, short flags);

#endif /* #ifndef TEAVPN2__NET__LINUX__IFACE_H */

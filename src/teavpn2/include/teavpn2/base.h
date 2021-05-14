// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/base.h
 *
 *  Base header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__BASE_H
#define TEAVPN2__BASE_H

#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <bluetea/base.h>


#ifndef INET_ADDRSTRLEN
#  define IPV4_L (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4_L (INET_ADDRSTRLEN)
#endif

#ifndef INET6_ADDRSTRLEN
#  define IPV6_L (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6_L (INET6_ADDRSTRLEN)
#endif

#define STR(a) #a
#define XSTR(a) STR(a)

#define TEAVPN2_VERSION \
	XSTR(VERSION) "." XSTR(PATCHLEVEL) "." XSTR(SUBLEVEL) EXTRAVERSION


typedef enum _sock_type {
	SOCK_TCP = 0,
	SOCK_UDP = 1
} sock_type;


struct if_info {
	char		dev[16];
	char		ipv4_pub[IPV4_L];
	char		ipv4[IPV4_L];
	char		ipv4_netmask[IPV4_L];
	char		ipv4_dgateway[IPV4_L];
#ifdef TEAVPN_IPV6_SUPPORT
	char		ipv6_pub[IPV6_L];
	char		ipv6[IPV6_L];
	char		ipv6_netmask[IPV6_L];
	char		ipv6_dgateway[IPV6_L];
#endif
	uint16_t	mtu;
};

#endif /* #ifndef TEAVPN2__BASE_H */

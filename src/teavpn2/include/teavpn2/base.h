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

#define IFACENAMESIZ (16u)

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


struct teavpn2_version {
	uint8_t		ver;
	uint8_t		patch_lvl;
	uint8_t		sub_lvl;
	char		extra[5];
};


static_assert(offsetof(struct teavpn2_version, ver) == 0,
	      "Bad offsetof(struct teavpn2_version, ver)");

static_assert(offsetof(struct teavpn2_version, patch_lvl) == 1,
	      "Bad offsetof(struct teavpn2_version, patch_lvl)");

static_assert(offsetof(struct teavpn2_version, sub_lvl) == 2,
	      "Bad offsetof(struct teavpn2_version, sub_lvl)");

static_assert(offsetof(struct teavpn2_version, extra) == 3,
	      "Bad offsetof(struct teavpn2_version, extra)");

static_assert(sizeof(struct teavpn2_version) == 8,
	      "Bad sizeof(struct teavpn2_version)");


struct if_info {
	char		dev[IFACENAMESIZ];
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


static_assert(IFACENAMESIZ == 16u, "Bad IFACENAMESIZ value");

static_assert(offsetof(struct if_info, dev) == 0,
	      "Bad offsetof(struct if_info, dev)");

static_assert(offsetof(struct if_info, ipv4_pub) == 16,
	      "Bad offsetof(struct if_info, ipv4_pub)");

static_assert(offsetof(struct if_info, ipv4) == 16 + (IPV4_L * 1),
	      "Bad offsetof(struct if_info, ipv4)");

static_assert(offsetof(struct if_info, ipv4_netmask) == 16 + (IPV4_L * 2),
	      "Bad offsetof(struct if_info, ipv4_netmask)");

static_assert(offsetof(struct if_info, ipv4_dgateway) == 16 + (IPV4_L * 3),
	      "Bad offsetof(struct if_info, ipv4_dgateway)");


#ifdef TEAVPN_IPV6_SUPPORT

/*
 * TODO: Add IPv6 static assert.
 */
static_assert(0, "Fixme: Add IPv6 static assert");

#else /* #ifdef TEAVPN_IPV6_SUPPORT */

static_assert(offsetof(struct if_info, mtu) == 16 + (IPV4_L * 4),
	      "Bad offsetof(struct if_info, mtu)");

static_assert(sizeof(struct if_info) == 16 + (IPV4_L * 4) + sizeof(uint16_t),
	      "Bad sizeof(struct if_info)");

#endif  /* #ifdef TEAVPN_IPV6_SUPPORT */


#endif /* #ifndef TEAVPN2__BASE_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__COMMON_H
#define TEAVPN2__COMMON_H

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <inttypes.h>

#include <teavpn2/print.h>
#include <teavpn2/allocator.h>

#include <emerg/emerg.h>

#include <teavpn2/compiler_attributes.h>

#ifndef unlikely
#  define unlikely(X) __builtin_expect((bool)(X), 0)
#endif

#ifndef likely
#  define likely(X) __builtin_expect((bool)(X), 1)
#endif

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#ifndef ____stringify
#  define ____stringify(EXPR) #EXPR
#endif

#ifndef __stringify
#  define __stringify(EXPR) ____stringify(EXPR)
#endif

#ifndef __acquires
#  define __acquires(LOCK)
#endif

#ifndef __releases
#  define __releases(LOCK)
#endif

#ifndef __must_hold
#  define __must_hold(LOCK)
#endif

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

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


#define TVPN_MAX_UNAME_LEN	(0x100u)
#define TVPN_MAX_PASS_LEN	(0x100u)

extern int run_client(int argc, char *argv[]);
extern int run_server(int argc, char *argv[]);

#define IFACENAMESIZ 16u

typedef enum _sock_type_t {
	SOCK_UDP,
	SOCK_TCP
} sock_type;

typedef sock_type sock_type_t;

typedef enum _event_loop_t {
	EVTL_NOP,
	EVTL_EPOLL,
	EVTL_IO_URING
} event_loop_t;


/* Make it 32 bytes in size. */
struct teavpn2_version {
	uint8_t		ver;
	uint8_t		patch_lvl;
	uint8_t		sub_lvl;
	char		extra[29];
};

static_assert(offsetof(struct teavpn2_version, ver) == 0,
	      "Bad offsetof(struct teavpn2_version, ver)");

static_assert(offsetof(struct teavpn2_version, patch_lvl) == 1,
	      "Bad offsetof(struct teavpn2_version, patch_lvl)");

static_assert(offsetof(struct teavpn2_version, sub_lvl) == 2,
	      "Bad offsetof(struct teavpn2_version, sub_lvl)");

static_assert(offsetof(struct teavpn2_version, extra) == 3,
	      "Bad offsetof(struct teavpn2_version, extra)");

static_assert(sizeof(struct teavpn2_version) == 32,
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
	uint16_t	ipv4_mtu;
#ifdef TEAVPN_IPV6_SUPPORT
	uint16_t	ipv6_mtu;
#endif
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

static_assert(offsetof(struct if_info, ipv4_mtu) == 16 + (IPV4_L * 4),
	      "Bad offsetof(struct if_info, mtu)");

static_assert(sizeof(struct if_info) == 16 + (IPV4_L * 4) + sizeof(uint16_t),
	      "Bad sizeof(struct if_info)");

#endif  /* #ifdef TEAVPN_IPV6_SUPPORT */

extern const char *data_dir;
extern void show_version(void);
extern bool teavpn2_auth(const char *username, const char *password,
			 struct if_info *iff);

static inline void *calloc_wrp(size_t nmemb, size_t size)
{
	int err;
	void *ret = al64_calloc(nmemb, size);
	if (unlikely(!ret)) {
		err = errno;
		/* The errno might change after pr_err, must backup! */
		pr_err("calloc_wrp: " PRERF, PREAR(err));
		errno = err;
	}
	return ret;
}


#if !defined(__clang__)
/*
 * GCC false positive warnings are annoying!
 */
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Warray-bounds"
#  pragma GCC diagnostic ignored "-Wstringop-overflow"
#  pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
static inline char *strncpy2(char *__restrict__ dst,
			     const char *__restrict__ src,
			     size_t n)
{
	char *ret = strncpy(dst, src, n);
	ret[n - 1] = '\0';
	return ret;
}
#if !defined(__clang__)
#  pragma GCC diagnostic pop
#endif


#endif

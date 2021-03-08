
#ifndef TEAVPN2____BASE_H
#define TEAVPN2____BASE_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <teavpn2/debug.h>
#include <teavpn2/vt_hexdump.h>

#define likely(EXPR)   __builtin_expect((EXPR), 1)
#define unlikely(EXPR) __builtin_expect((EXPR), 0)

#define STATIC_ASSERT(EXPR, ASSERT) _Static_assert((EXPR), ASSERT)

#ifndef offsetof
#  define offsetof(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT))
#endif

#ifndef INET_ADDRSTRLEN
#  define IPV4LEN (sizeof("xxx.xxx.xxx.xxx"))
#else
#  define IPV4LEN (INET_ADDRSTRLEN)
#endif

#ifndef INET6_ADDRSTRLEN
#  define IPV6LEN (sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxx.xxx.xxx.xxx"))
#else
#  define IPV6LEN (INET6_ADDRSTRLEN)
#endif

#define IPV4SLEN (IPV4LEN + 16)
#define IPV6SLEN (IPV6LEN + 16)

#ifndef __inline
#  define __inline inline
#endif

#ifndef __always_inline
#  define __always_inline __inline __attribute__((always_inline))
#endif

#ifndef __no_inline
#  define __no_inline __attribute__((noinline))
#endif


#define PRERR "(%d) %s"
#define PREAG(NUM) NUM, strerror(NUM)


struct ver_info {
	uint8_t		ver;
	uint8_t		sub_ver;
	uint8_t		sub_sub_ver;
};

struct iface_cfg {
	char		dev[16];
	char		ipv4[IPV4SLEN];
	char		ipv4_netmask[IPV4SLEN];
	char		def_gateway[IPV4SLEN];
	uint16_t	mtu;
};

STATIC_ASSERT(sizeof(uint8_t) == 1, "Bad sizeof(uint8_t)");
STATIC_ASSERT(sizeof(uint16_t) == 2, "Bad sizeof(uint16_t)");
STATIC_ASSERT(sizeof(uint32_t) == 4, "Bad sizeof(uint32_t)");
STATIC_ASSERT(sizeof(uint64_t) == 8, "Bad sizeof(uint64_t)");

STATIC_ASSERT(
	sizeof(struct ver_info) == 3,
	"Bad sizeof(struct ver_info)"
);
STATIC_ASSERT(
	offsetof(struct ver_info, ver) == 0,
	"Bad offsetof(struct ver_info, ver)"
);
STATIC_ASSERT(
	offsetof(struct ver_info, sub_ver) == 1,
	"Bad offsetof(struct ver_info, sub_ver)"
);
STATIC_ASSERT(
	offsetof(struct ver_info, sub_sub_ver) == 2,
	"Bad offsetof(struct ver_info, sub_sub_ver)"
);
STATIC_ASSERT(
	sizeof(struct iface_cfg) == (
		16 + (IPV4SLEN * 3) + 2
	),
	"Bad sizeof(struct iface_cfg)"
);
STATIC_ASSERT(
	offsetof(struct iface_cfg, dev) == 0,
	"Bad offsetof(struct iface_cfg, dev)"
);
STATIC_ASSERT(
	offsetof(struct iface_cfg, ipv4) == 16,
	"Bad offsetof(struct iface_cfg, ipv4)"
);
STATIC_ASSERT(
	offsetof(struct iface_cfg, ipv4_netmask) == (16 + IPV4SLEN),
	"Bad offsetof(struct iface_cfg, ipv4_netmask)"
);
STATIC_ASSERT(
	offsetof(struct iface_cfg, def_gateway) == (16 + IPV4SLEN * 2),
	"Bad offsetof(struct iface_cfg, def_gateway)"
);
STATIC_ASSERT(
	offsetof(struct iface_cfg, mtu) == (16 + (IPV4SLEN * 3)),
	"Bad offsetof(struct iface_cfg, mtu)"
);


typedef enum {
	SOCK_TCP = 0,
	SOCK_UDP = 1
} sock_type;

#endif /* #ifndef TEAVPN2____BASE_H */

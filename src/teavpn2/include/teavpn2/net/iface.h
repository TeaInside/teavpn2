
#ifndef TEAVPN2__NET__IFACE_H
#define TEAVPN2__NET__IFACE_H

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <teavpn2/base.h>


struct iface_cfg {
	char		dev[16];
	char		ipv4_pub[IPV4_L];
	char		ipv4[IPV4_L];
	char		ipv4_netmask[IPV4_L];
	char		ipv4_dgateway[IPV4_L];
#ifdef TEAVPN_IPV6_SUPPORT
	char		ipv6[IPV6_L];
	char		ipv6_netmask[IPV6_L];
	char		ipv6_dgateway[IPV6_L];
#endif
	uint16_t	mtu;
};


static_assert(sizeof(struct iface_cfg) == (
		16		/* dev    */
		+ (IPV4_L * 4)	/* ipvr_* */
		+ 2		/* mtu    */
	     ),
	     "Bad sizeof(struct iface_cfg)");


static_assert(offsetof(struct iface_cfg, dev) == 0,
	      "Bad offsetof(struct iface_cfg, dev)");

static_assert(offsetof(struct iface_cfg, ipv4_pub)      == 16 + (IPV4_L * 0),
	      "Bad offsetof(struct iface_cfg, ipv4_pub)");

static_assert(offsetof(struct iface_cfg, ipv4)          == 16 + (IPV4_L * 1),
	      "Bad offsetof(struct iface_cfg, ipv4)");

static_assert(offsetof(struct iface_cfg, ipv4_netmask)  == 16 + (IPV4_L * 2),
	      "Bad offsetof(struct iface_cfg, ipv4_netmask)");

static_assert(offsetof(struct iface_cfg, ipv4_dgateway) == 16 + (IPV4_L * 3),
	      "Bad offsetof(struct iface_cfg, ipv4_dgateway)");

static_assert(offsetof(struct iface_cfg, mtu)           == 16 + (IPV4_L * 4),
	      "Bad offsetof(struct iface_cfg, mtu)");

bool teavpn_iface_up(struct iface_cfg *iface);
bool teavpn_iface_down(struct iface_cfg *iface);

#if defined(__linux__)
#  include <teavpn2/net/linux/iface.h>
#endif

#endif /* #ifndef TEAVPN2__NET__IFACE_H */

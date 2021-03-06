
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


bool teavpn_iface_up(struct iface_cfg *iface);

#endif /* #ifndef TEAVPN2__NET__IFACE_H */

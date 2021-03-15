
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef TEAVPN2__SERVER__LINUX__IFACE_H
#define TEAVPN2__SERVER__LINUX__IFACE_H

#include <teavpn2/server/common.h>
#include <teavpn2/server/linux/tcp.h>

int teavpn_tcp_init_iface(struct srv_tcp_state *state);

#endif /* #ifndef TEAVPN2__SERVER__LINUX__IFACE_H */

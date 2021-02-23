
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef __TEAVPN2__SERVER__LINUX__IFACE_H
#define __TEAVPN2__SERVER__LINUX__IFACE_H

#include <teavpn2/server/common.h>
#include <teavpn2/server/linux/tcp.h>

int init_iface_tcp_server(struct srv_tcp_state *state);

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__IFACE_H */

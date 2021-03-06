
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef TEAVPN2__CLIENT__LINUX__IFACE_H
#define TEAVPN2__CLIENT__LINUX__IFACE_H

#include <teavpn2/client/common.h>
#include <teavpn2/client/linux/tcp.h>

int init_iface_tcp_client(struct cli_tcp_state *state);

#endif /* #ifndef TEAVPN2__CLIENT__LINUX__IFACE_H */

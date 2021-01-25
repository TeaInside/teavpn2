
#if !defined(__linux__)
# error This header file must only be used for Linux
#endif

#ifndef __TEAVPN2__SERVER__PLAT__LINUX__TCP_H
#define __TEAVPN2__SERVER__PLAT__LINUX__TCP_H

#include <teavpn2/server/common.h>

int teavpn_tcp_server(struct srv_cfg *cfg);

#endif /* #ifndef __TEAVPN2__SERVER__PLAT__LINUX__TCP_H */

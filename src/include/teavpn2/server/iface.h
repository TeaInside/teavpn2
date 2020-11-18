
#ifndef TEAVPN2__SERVER__IFACE_H
#define TEAVPN2__SERVER__IFACE_H

#include <teavpn2/server/common.h>

#if defined(__linux__)
#  include <teavpn2/server/iface/linux.h>
#else
#  error Compiler is not supported!
#endif

int
srv_iface_init(srv_iface_cfg *iface);

#endif

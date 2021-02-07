
#ifndef TEAVPN2__GLOBAL__HELPERS__IFACE_H
#define TEAVPN2__GLOBAL__HELPERS__IFACE_H

#include <stdbool.h>

#if defined(__linux__)

int
tun_alloc(char *dev, int flags);

int
tun_set_queue(int fd, bool enable);

#else /* #if defined(__linux__) */
#  error "Compiler is not supported!"
#endif /* #if defined(__linux__) */

#endif

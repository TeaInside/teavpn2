
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <teavpn2/global/debug.h>
#include <teavpn2/global/memory.h>

typedef enum {
  sock_tcp,
  sock_udp
} socket_type;


char *escapeshellarg(char *alloc, char *str);

#ifndef OFFSETOF
#define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT)) 
#endif

int tun_alloc(char *dev, int flags);
int tun_set_queue(int fd, int enable);

#endif

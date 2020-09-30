
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <teavpn2/global/memory.h>

typedef enum {
  sock_tcp,
  sock_udp
} socket_type;

void t_ar_init(register void *ptr, register size_t len);
void *t_ar_alloc(register size_t len);
char *t_ar_strdup(register const char *str);
char *t_ar_strndup(register const char *str, register size_t tlen);

#endif

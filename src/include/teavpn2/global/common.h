
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <teavpn2/global/debug.h>
#include <teavpn2/global/memory.h>

#define CLIENT_DATA_SIZE (6144)


#ifndef OFFSETOF
#define OFFSETOF(TYPE, ELEMENT) ((size_t)&(((TYPE *)0)->ELEMENT)) 
#endif

#define likely(EXPR)   __builtin_expect((EXPR), 1)
#define unlikely(EXPR) __builtin_expect((EXPR), 0)

typedef enum {
  sock_tcp,
  sock_udp
} socket_type;

typedef enum {
  TCP_PKT_PING        = (1 << 0),
  TCP_PKT_AUTH        = (1 << 1),
  TCP_PKT_DATA        = (1 << 2),
  TCP_PKT_DISCONNECT  = (1 << 3),
} packet_type;

typedef struct __attribute__((__packed__)) _auth_pkt {
  uint8_t           username_len;
  uint8_t           password_len;
  char              username[255];
  char              password[255];
} auth_pkt;

typedef struct __attribute__((__packed__)) _client_pkt {
  packet_type       type;
  uint16_t          size;                     /* The size of data to be sent. */
  char              data[CLIENT_DATA_SIZE];
} client_pkt;

#define IDENTIFIER_PKT_SIZE (OFFSETOF(client_pkt, data))

char *escapeshellarg(char *alloc, char *str);

int tun_alloc(char *dev, int flags);
int tun_set_queue(int fd, int enable);

#define TCP_BUFFER (CLIENT_DATA_SIZE)
#define TCP_RECV_BUFFER (TCP_BUFFER)
#define TCP_SEND_BUFFER (TCP_BUFFER)

#endif

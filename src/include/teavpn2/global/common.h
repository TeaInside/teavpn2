
#ifndef TEAVPN2__GLOBAL__COMMON_H
#define TEAVPN2__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/types.h>

#include <teavpn2/global/debug.h>
#include <teavpn2/global/memory.h>

#define DATA_SIZE (8096)


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
  CLI_PKT_PING        = (1 << 0),
  CLI_PKT_AUTH        = (1 << 1),
  CLI_PKT_DATA        = (1 << 2),
  CLI_PKT_DISCONNECT  = (1 << 3),
} cli_packet_type;

typedef enum {
  SRV_PKT_PING        = (1 << 0),
  SRV_PKT_AUTH_OK     = (1 << 1),
  SRV_PKT_AUTH_REJECT = (1 << 2),
  SRV_PKT_DATA        = (1 << 3),
  SRV_PKT_DISCONNECT  = (1 << 4),
} srv_packet_type;

typedef struct __attribute__((__packed__)) _auth_pkt {
  uint8_t           username_len;
  uint8_t           password_len;
  char              username[255];
  char              password[255];
} auth_pkt;

typedef struct __attribute__((__packed__)) _srv_auth_res {
  __be32            ipv4;
  __be32            ipv4_netmask;
} srv_auth_res;

typedef struct __attribute__((__packed__)) _client_pkt {
  cli_packet_type   type;
  uint16_t          size;                     /* The size of data to be sent. */
  char              data[DATA_SIZE];
} client_pkt;

typedef struct __attribute__((__packed__)) _server_pkt {
  srv_packet_type   type;
  uint16_t          size;                     /* The size of data to be sent. */
  char              data[DATA_SIZE];
} server_pkt;

#define CLI_IDENT_PKT_SIZE (OFFSETOF(client_pkt, data))
#define SRV_IDENT_PKT_SIZE (OFFSETOF(client_pkt, data))

char *escapeshellarg(char *alloc, char *str);

int tun_alloc(char *dev, int flags);
int tun_set_queue(int fd, int enable);
uint8_t cidr_jump_table(__be32 netmask);
int fd_set_nonblock(int fd);

#define TCP_RECV_BUFFER DATA_SIZE
#define TCP_SEND_BUFFER DATA_SIZE

#endif

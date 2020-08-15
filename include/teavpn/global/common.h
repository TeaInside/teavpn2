
#ifndef TEAVPN__GLOBAL__COMMON_H
#define TEAVPN__GLOBAL__COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

/* 
 * Socket communication type.
 */
enum socket_type {
  TEAVPN_SOCK_TCP = 1,
  TEAVPN_SOCK_UDP = 2
};

/* Authentication data. */
typedef struct _teavpn_auth {
  char  username[64];
  char  password[255];
} teavpn_auth;

/* Client packet type. */
typedef enum {
  CLI_PKT_AUTH  = 1,
  CLI_PKT_DATA  = 2,
  CLI_PKT_CLOSE = 3,
} cli_pkt_type;

/* Client packet. */
typedef struct _cli_pkt {
  cli_pkt_type  type;     /* Packet type */
  uint16_t      len;      /* Length of data. */
  char          data[1];  /* Data (struct hack), its length must be equal to len. */
} cli_pkt;

#endif

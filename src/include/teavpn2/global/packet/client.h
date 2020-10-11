
#ifndef TEAVPN2__GLOBAL__PACKET__CLIENT_H
#define TEAVPN2__GLOBAL__PACKET__CLIENT_H

#include <stdint.h>

/*
 * Data structures for client packet.
 */

#ifndef CL_PKT_DSIZE
#  define CL_PKT_DSIZE (6144)
#endif

typedef struct __attribute__((__packed__)) _cl_pkt_auth {
  uint8_t           username_len;
  uint8_t           password_len;
  char              data[510];
} cl_pkt_auth;


typedef struct __attribute__((__packed__)) _cl_pkt_data {
  uint16_t          len;
  char              data[1];      /* Must be struct hack. */
} cl_pkt_data;


typedef enum _cl_pkt_type {
  CL_PKT_PING       = 0x1,
  CL_PKT_AUTH       = 0x2,
  CL_PKT_DATA       = 0x3,
  CL_PKT_DISCONNECT = 0x4
} __attribute__ ((__packed__)) cl_pkt_type;

typedef struct __attribute__((__packed__)) _cl_pkt {
  cl_pkt_type       type;
  uint16_t          len;
  char              data[CL_PKT_DSIZE];
} cl_pkt;

#define CL_IDENT_SZ (OFFSETOF(cl_pkt, data))

ST_ASSERT((CL_IDENT_SZ == (sizeof(cl_pkt_type) + sizeof(uint16_t))));
ST_ASSERT(sizeof(cl_pkt_type) == 1);

#endif


#ifndef TEAVPN2__GLOBAL__PACKET__SERVER_H
#define TEAVPN2__GLOBAL__PACKET__SERVER_H

#include <stdint.h>

/*
 * Data structures for server packet.
 */

#ifndef SE_PKT_DSIZE
#  define SE_PKT_DSIZE (6144)
#endif

/* ======================================================= */
/*
 * Server packet auth info.
 *
 * This packet determine server auth requirement.
 */

typedef enum {
  SE_AUTH_NO_AUTH  = 0x0,
  SE_AUTH_REQUIRED = 0x1
} se_auth_info;


typedef struct __attribute__((__packed__)) _se_pkt_auth_info {
  se_auth_info  type;
} se_pkt_auth_info;
/* end */
/* ======================================================= */


/* ======================================================= */
/*
 * Server packet auth response.
 *
 * This packet contains authentication response. When the client
 * sends auth packet to the server, the server should give a
 * response with this packet.
 *
 * If auth success, the data[] in this struct must contain private
 * IP for client.
 */

typedef enum {
  SE_AUTH_RES_REJECTED = 0x0,
  SE_AUTH_RES_ACCEPTED = 0x1,
} se_auth_res;

typedef struct __attribute__((__packed__)) _se_pkt_auth_res {
  se_auth_res           type;
  uint16_t              len;
  char                  data[1];  /* Struct hack. */
} se_pkt_auth_res;
/* end */
/* ======================================================= */


/* ======================================================= */
typedef struct __attribute__((__packed__)) _se_pkt_data {
  uint16_t            len;
  char                data[1];    /* Struct hack. */
} se_pkt_data;
/* end */
/* ======================================================= */


/* ======================================================= */
typedef enum {
  SE_PKT_PING        = 0x1,
  SE_PKT_AUTH_INFO   = 0x2,
  SE_PKT_AUTH_RES    = 0x3,
  SE_PKT_DATA        = 0x4,
  SE_PKT_DISCONNECT  = 0x5,
} __attribute__ ((__packed__))  se_pkt_type;


typedef struct __attribute__((__packed__)) _se_pkt {
  se_pkt_type       type;
  uint16_t          len;
  char              data[SE_PKT_DSIZE];
} se_pkt;
/* end */
/* ======================================================= */

#define SE_IDENT_SZ (OFFSETOF(se_pkt, data))

ST_ASSERT((SE_IDENT_SZ == (sizeof(se_pkt_type) + sizeof(uint16_t))));
ST_ASSERT(sizeof(se_pkt_type) == 1);

#endif

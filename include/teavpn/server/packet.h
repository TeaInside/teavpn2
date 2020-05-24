
#ifndef __TEAVPN__SERVER__PACKET_H
#define __TEAVPN__SERVER__PACKET_H

#include <stdint.h>

enum teavpn_srv_pkt_type {
  SRV_PKT_NULL,
  SRV_PKT_AUTH_REQUIRED,
  SRV_PKT_AUTH_REJECTED,
  SRV_PKT_AUTH_ACCEPTED,
  SRV_PKT_CHAN_IS_FULL,
  SRV_PKT_IFACE_DATA,
  SRV_PKT_MSG
};

typedef struct __attribute__((__packed__)) {
  /* Must be null terminated. */
  char inet4[24];
  char inet4_bc[24];
} teavpn_pkt_iface;

typedef struct __attribute__((__packed__)) {
  uint16_t msg_len;
  char msg[1];
} teavpn_pkt_msg;

typedef struct __attribute__((__packed__)) {
  enum teavpn_srv_pkt_type type;
  uint16_t len;
  char data[1];
} teavpn_srv_pkt;

#define SRV_PKT_MSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)

#endif

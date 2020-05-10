
#ifndef TEAVPN__SERVER__DATA_STRUCT_H
#define TEAVPN__SERVER__DATA_STRUCT_H

#include <stdint.h>

#define SRV_PKT_MSG           1
#define SRV_PKT_DATA          2
#define SRV_PKT_AUTH_REQUIRED 3
#define SRV_PKT_AUTH_REJECTED 4
#define SRV_PKT_AUTH_ACCEPTED 5
#define SRV_PKT_IFACE_INFO    6

enum teavpn_server_packet_type {
  srv_pkt_type_msg            = SRV_PKT_MSG,
  srv_pkt_type_data           = SRV_PKT_DATA,
  srv_pkt_type_auth_required  = SRV_PKT_AUTH_REQUIRED,
  srv_pkt_type_auth_rejected  = SRV_PKT_AUTH_REJECTED,
  srv_pkt_type_auth_accepted  = SRV_PKT_AUTH_ACCEPTED,
  srv_pkt_iface_info          = SRV_PKT_IFACE_INFO
};


typedef struct __attribute__((__packed__)) {
  /* Must be null terminated. */
  char inet4[64];
  char inet4_bc[64];
} teavpn_srv_iface_info;

typedef struct __attribute__((__packed__)) {

  enum teavpn_server_packet_type type;
  uint16_t len; // length of data.
  char data[1]; // struct hack.

} teavpn_srv_pkt;


#endif

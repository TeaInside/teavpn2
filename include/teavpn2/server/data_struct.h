
#ifndef TEAVPN__SERVER__DATA_STRUCT_H
#define TEAVPN__SERVER__DATA_STRUCT_H

#include <stdint.h>

#define SRV_PKT_MSG           (1 << 0)
#define SRV_PKT_DATA          (1 << 1)
#define SRV_PKT_AUTH_REQUIRED (1 << 2)

enum teavpn_server_packet_type {
  srv_pkt_type_msg            = SRV_PKT_MSG,
  srv_pkt_type_data           = SRV_PKT_DATA,
  srv_pkt_type_auth_required  = SRV_PKT_AUTH_REQUIRED
};

typedef struct __attribute__((__packed__)) {

  enum teavpn_server_packet_type type;
  uint16_t len; // length of data.
  char data[1]; // struct hack.

} teavpn_srv_pkt;


#endif

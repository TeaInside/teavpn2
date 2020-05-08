
#ifndef TEAVPN__SERVER__DATA_STRUCT_H
#define TEAVPN__SERVER__DATA_STRUCT_H

#include <stdint.h>

struct teavpn_server_msg {

};

struct teavpn_server_data {

};

struct teavpn_server_auth {

};

#define SRV_PKT_MSG  (1 << 0)
#define SRV_PKT_DATA (1 << 1)
#define SRV_PKT_AUTH (1 << 2)

enum teavpn_server_packet_type {
  srv_pkt_type_msg = SRV_PKT_MSG,
  srv_pkt_type_data = SRV_PKT_DATA,
  srv_pkt_type_auth = SRV_PKT_AUTH
};

union teavpn_server_packet {
  struct teavpn_server_msg msg;
  struct teavpn_server_data data;
  struct teavpn_server_auth auth;
};

typedef struct {
  enum teavpn_server_packet_type type;
  uint32_t len;
  union teavpn_server_packet packet;
} teavpn_srv_pkt;

#endif

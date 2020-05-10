
#ifndef TEAVPN__CLIENT__DATA_STRUCT_H
#define TEAVPN__CLIENT__DATA_STRUCT_H

#define CLI_PKT_MSG  (1 << 0)
#define CLI_PKT_DATA (1 << 1)
#define CLI_PKT_AUTH (1 << 2)

enum teavpn_client_packet_type {
  cli_pkt_type_msg   = CLI_PKT_MSG,
  cli_pkt_type_data  = CLI_PKT_DATA,
  cli_pkt_type_auth  = CLI_PKT_AUTH
};

typedef struct __attribute__((__packed__)) {
  /* Must be null terminated. */
  char username[255];
  char password[255];
} teavpn_cli_auth;

typedef struct __attribute__((__packed__)) {

  enum teavpn_client_packet_type type;
  uint16_t len; // length of data.
  char data[1]; // struct hack.

} teavpn_cli_pkt;


#endif

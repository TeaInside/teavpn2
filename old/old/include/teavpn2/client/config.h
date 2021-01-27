
#ifndef TEAVPN__CLIENT__CONFIG_H
#define TEAVPN__CLIENT__CONFIG_H

#include <teavpn2/global/config.h>

typedef struct {
  char *config_file;
  struct teavpn_iface iface;
  enum teavpn_socket_type socket_type;
  struct {
    char *server_addr;
    uint16_t server_port;
  } socket;
  struct {
    char *username;
    char *password;
  } auth;
  void *mstate;
} teavpn_client_config;

#endif


#ifndef TEAVPN2__CLIENT__CONFIG_H
#define TEAVPN2__CLIENT__CONFIG_H

#include <stdint.h>

/* ======================================================= */
/* Virtual network interface configuration. */
typedef struct _client_iface_cfg {
  char                  *dev;           /* Interface name. */
  char                  *ipv4;          /* IPv4.           */
  char                  *ipv4_netmask;  /* IPv4 netmask.   */
  char                  *ipv4_gateway;  /* IPv4 gateway.   */
#if 0
  char                  *ipv6;          /* IPv4.           */
  char                  *ipv6_netmask;  /* IPv6 netmask.   */
  char                  *ipv6_gateway;  /* IPv6 gateway.   */
#endif
  uint16_t              mtu;            /* MTU.            */
} client_iface_cfg;
/* ======================================================= */


/* ======================================================= */
/* Target server configuration. */
typedef struct _client_socket_cfg {
  char                  *server_addr;   /* Socket client bind address. */
  uint16_t              server_port;    /* Socket client bind port.    */
  socket_type           type;           /* Socket type, TCP/UDP.       */
} client_socket_cfg;
/* ======================================================= */


/* ======================================================= */
/* Auth configuration. */
typedef struct _client_auth_cfg {
  char                  *username;
  char                  *password;
  char                  *secret_key;    /* Pre-shared key. */
} client_auth_cfg;
/* ======================================================= */


/* ======================================================= */
typedef struct _client_cfg {
  char                  *config_file;   /* Config file.                     */
  char                  *data_dir;      /* Data directory.                  */
  client_iface_cfg      iface;          /* Virtual interface configuration. */
  client_socket_cfg     sock;           /* Socket configuration.            */
  client_auth_cfg       auth;
} client_cfg;
/* ======================================================= */

#endif


#ifndef TEAVPN2__SERVER__CONFIG_H
#define TEAVPN2__SERVER__CONFIG_H

#include <stdint.h>

/* ======================================================= */
/* Virtual network interface configuration. */
typedef struct _server_iface_cfg {
  char                  *dev;            /* Interface name. */
  char                  *ipv4;           /* IPv4.           */
  char                  *ipv4_netmask;   /* IPv4 netmask.   */
#if 0
  char                  *ipv6;           /* IPv6.           */
  char                  *ipv6_netmask;   /* IPv6 netmask.   */
#endif
  uint16_t              mtu;             /* MTU.            */
} server_iface_cfg;
/* ======================================================= */


/* ======================================================= */
/* Socket server configuration. */
typedef struct _server_socket_cfg {
  char                  *bind_addr;     /* Socket server bind address. */
  int                   backlog;        /* Socket listen backlog.      */
  uint16_t              bind_port;      /* Socket server bind port.    */
  socket_type           type;           /* Socket type, TCP/UDP.       */
  uint16_t              max_conn;       /* Max connections.            */
} server_socket_cfg;
/* ======================================================= */


/* ======================================================= */
typedef struct _server_cfg {
  char                  *config_file;   /* Config file.                     */
  char                  *data_dir;      /* Data directory.                  */
  server_iface_cfg      iface;          /* Virtual interface configuration. */
  server_socket_cfg     sock;           /* Socket configuration.            */
} server_cfg;
/* ======================================================= */

#endif

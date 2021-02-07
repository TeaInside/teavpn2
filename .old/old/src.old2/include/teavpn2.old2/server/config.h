
#ifndef TEAVPN2__SERVER__CONFIG_H
#define TEAVPN2__SERVER__CONFIG_H


#include <teavpn2/global/types.h>

/* Virtual network interface configuration. */
typedef struct _srv_iface_cfg {
  char                  *dev;            /* Interface name. */
  char                  *ipv4;           /* IPv4.           */
  char                  *ipv4_netmask;   /* IPv4 netmask.   */
#if 0
  char                  *ipv6;           /* IPv6.           */
  char                  *ipv6_netmask;   /* IPv6 netmask.   */
#endif
  uint16_t              mtu;             /* MTU.            */
} srv_iface_cfg;


/* Socket server configuration. */
typedef struct _srv_sock_cfg {
  char                  *bind_addr;     /* Socket server bind address. */
  int                   backlog;        /* Socket listen backlog.      */
  uint16_t              bind_port;      /* Socket server bind port.    */
  sock_type             type;           /* Socket type, TCP/UDP.       */
  uint16_t              max_conn;       /* Max connections.            */
} srv_sock_cfg;


/* Server configuration. */
typedef struct _srv_cfg {
  char                  *config_file;   /* Config file.                     */
  char                  *data_dir;      /* Data directory.                  */
  srv_iface_cfg         iface;          /* Virtual interface configuration. */
  srv_sock_cfg          sock;           /* Socket configuration.            */
} srv_cfg;


bool
tvpn_srv_load_cfg_file(char *file, srv_cfg *cfg);


#endif /* #ifndef TEAVPN2__SERVER__CONFIG_H */

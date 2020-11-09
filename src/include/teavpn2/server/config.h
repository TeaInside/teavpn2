
#ifndef TEAVPN2__SERVER__CONFIG_H
#define TEAVPN2__SERVER__CONFIG_H

#include <teavpn2/server/common.h>

/* Virtual network interface configuration. */
typedef struct _iface_cfg
{
  char            *dev;           /* Virtual network interface name. */
  char            *ipv4;          /* IPv4                            */
  char            *ipv4_netmask;  /* IPv4 netmask                    */
#ifdef TEAVPN_IPV6_SUPPORT
  char            *ipv6;          /* IPv6                            */
  char            *ipv6_netmask;  /* IP6 netmask                     */
#endif
  uint16_t        mtu;            /* MTU                             */
} srv_iface_cfg;


/* Socket server configuration. */
typedef struct _sock_cfg
{
  sock_type       type;           /* Socket type (TCP/UDP).          */
  char            *bind_addr;     /* Bind address.                   */
  uint16_t        bind_port;      /* Bind port.                      */
  uint16_t        max_conn;       /* Max connections.                */
  int             backlog;        /* Socket backlog.                 */
} srv_sock_cfg;


/* TeaVPN server configuration structure. */
typedef struct _srv_cfg
{
  char            *cfg_file;      /* Config file to be loaded.       */
  char            *data_dir;      /* Data directory.                 */
  srv_sock_cfg    sock;
  srv_iface_cfg   iface;
} srv_cfg;


#ifndef CFG_DEBUG
#  define CFG_DEBUG 1
#endif

#if CFG_DEBUG
#  define PRINT_CFG(A, B) dbg_printf(argv_debug, #B " = " A "\n", (B))
#else
#  define PRINT_CFG(A, B)
#endif

inline static void
print_cfg(srv_cfg *cfg)
{
  PRINT_CFG("%s", cfg->cfg_file);
  PRINT_CFG("%s", cfg->data_dir);

  PRINT_CFG("%d", cfg->sock.type);
  PRINT_CFG("%s", cfg->sock.bind_addr);
  PRINT_CFG("%d", cfg->sock.bind_port);
  PRINT_CFG("%d", cfg->sock.max_conn);
  PRINT_CFG("%d", cfg->sock.backlog);

  PRINT_CFG("%s", cfg->iface.dev);
  PRINT_CFG("%s", cfg->iface.ipv4);
  PRINT_CFG("%s", cfg->iface.ipv4_netmask);
  PRINT_CFG("%d", cfg->iface.mtu);
}

#endif

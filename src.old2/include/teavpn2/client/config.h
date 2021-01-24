

#ifndef DO_INCLUDE_CONFIG_H
#  error <teavpn2/server/config.h> must be included from \
         <teavpn2/server/common.h>
#endif


#ifndef TEAVPN2__CLIENT__CONFIG_H
#define TEAVPN2__CLIENT__CONFIG_H

typedef struct _cli_iface_cfg
{
  char            *dev;           /* Virtual network interface name. */
  uint16_t        mtu;            /* MTU                             */
} cli_iface_cfg;

typedef struct _cli_sock_cfg
{
  sock_type       type;           /* Socket type (TCP/UDP).          */
  char            *srv_addr;      /* Server address.                 */
  uint16_t        srv_port;       /* Server port.                    */
} cli_sock_cfg;

typedef struct _cli_auth
{
  char            *username;
  char            *password;
  char            *secret_key;
} cli_auth;

typedef struct _cli_cfg
{
  char            *cfg_file;      /* Config file to be loaded.       */
  char            *data_dir;      /* Data directory.                 */
  cli_sock_cfg    sock;
  cli_iface_cfg   iface;
  cli_auth        auth;
} cli_cfg;


#ifndef CFG_DEBUG
#  define CFG_DEBUG 1
#endif

#if CFG_DEBUG
#  define PRINT_CFG(A, B) dbg_printf(argv_debug, #B " = " A, (B))
#else
#  define PRINT_CFG(A, B)
#endif


inline static void
print_cli_cfg(cli_cfg *cfg)
{
  PRINT_CFG("%s", cfg->cfg_file);
  PRINT_CFG("%s", cfg->data_dir);

  PRINT_CFG("%d", cfg->sock.type);
  PRINT_CFG("%s", cfg->sock.srv_addr);
  PRINT_CFG("%d", cfg->sock.srv_port);

  PRINT_CFG("%s", cfg->iface.dev);
  PRINT_CFG("%d", cfg->iface.mtu);

  PRINT_CFG("%s", cfg->auth.username);
  PRINT_CFG("%s", cfg->auth.password);
  PRINT_CFG("%s", cfg->auth.secret_key);
  (void)cfg;
}

#endif /* #ifndef TEAVPN2__CLIENT__CONFIG_H */

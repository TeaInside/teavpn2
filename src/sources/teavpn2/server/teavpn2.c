

#include <teavpn2/server/common.h>

#if defined(__linux__)
#  include <teavpn2/server/vpn/linux_inline_contracts.h>
#  include "vpn/tcp/linux.h"
#  include "vpn/udp/linux.h"
#  include "vpn/iface/linux.h"
#else
#  error Compiler is not supported!
#endif


inline static bool
tsrv_validate_cfg(srv_cfg *cfg);


/**
 * @param srv_cfg *cfg
 * @return int
 */
int
tsrv_run(srv_cfg *cfg)
{
  int retval = 1;

  if (!tsrv_validate_cfg(cfg)) {
    goto ret;
  }


  switch (cfg->sock.type) {
    case SOCK_TCP:
      retval = tsrv_run_tcp(cfg);
      break;

    case SOCK_UDP:
      // retval = tsrv_run_udp(cfg);
      printf("UDP socket is not supported yet!\n");
      break;

    default:
      err_printf("Invalid sock.type: %d", cfg->sock.type);
      break;
  }


ret:
  return retval;
}


/** 
 * @param srv_cfg *cfg
 * @return bool
 */
inline static bool
tsrv_validate_cfg(srv_cfg *cfg)
{
  srv_iface_cfg *iface = &(cfg->iface);
  srv_sock_cfg  *sock  = &(cfg->sock);


  {
    if (cfg->data_dir == NULL) {
      err_cfg_pr("cfg->data_dir cannot be empty!");
      goto err;
    }
  }


  {
    /* Validate virtual network interface config. */
    if (iface->dev == NULL) {
      err_cfg_pr("cfg->iface->dev cannot be empty!");
      goto err;
    }

    if (iface->ipv4 == NULL) {
      err_cfg_pr("cfg->iface->ipv4 cannot be empty!");
      goto err;
    }

    if (iface->ipv4_netmask == NULL) {
      err_cfg_pr("cfg->iface->ipv4_netmask cannot be empty!");
      goto err;
    }

    if (iface->mtu == 0) {
      err_cfg_pr("cfg->iface->mtu cannot be zero!");
      goto err;
    }
  }


  {
    /* Validate socket config. */
    if ((sock->type != SOCK_TCP) && (sock->type != SOCK_UDP)) {
      err_cfg_pr("Invalid cfg->sock->type with value: %d "
                 "(must be TCP (%d) or UDP (%d))",
                 sock->type, SOCK_TCP, SOCK_UDP);
      goto err;
    }

    if (sock->bind_addr == NULL) {
      err_cfg_pr("cfg->sock->bind_addr cannot be empty!");
      goto err;
    }

    if (sock->bind_port == 0) {
      err_cfg_pr("cfg->sock->bind_port cannot be zero!");
      goto err;
    }

    if (sock->max_conn == 0) {
      err_cfg_pr("cfg->sock->max_conn cannot be zero!");
      goto err;
    }
  }


  return true;

err:
  return false;
}

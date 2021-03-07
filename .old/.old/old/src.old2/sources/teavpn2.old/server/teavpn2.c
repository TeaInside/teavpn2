

#include <teavpn2/server/common.h>
#include <teavpn2/server/teavpn2.h>
#include <teavpn2/server/tcp.h>

static inline bool
tvpn_srv_config_validate(srv_cfg *cfg);

/**
 * @param srv_cfg *cfg
 * @return int
 */
int
tvpn_srv_run(srv_cfg *cfg)
{
  int ret = 1;

  if (!tvpn_srv_config_validate(cfg)) {
    goto ret;
  }

  switch (cfg->sock.type) {
    case SOCK_TCP:
      ret = tvpn_srv_tcp_run(cfg);
      break;

    case SOCK_UDP:
      debug_log(0, "UDP socket is not supported yet!");
      break;

    default:
      debug_log(0, "Invalid socket type %d", cfg->sock.type);
      break;
  }

ret:
  return ret;
}

/**
 * @param srv_cfg *cfg
 * @return bool
 */
static inline bool
tvpn_srv_config_validate(srv_cfg *cfg)
{
  debug_log(4, "Validating server config...");

  {
    /* Validate srv_iface_cfg. */
    srv_iface_cfg *iface = &(cfg->iface);

    if (!iface->dev) {
      debug_log(0, "cfg->iface.dev cannot be empty\n");
      return false;
    }

    if (!iface->ipv4) {
      debug_log(0, "cfg->iface.ipv4 cannot be empty\n");
      return false;
    }

    if (!iface->ipv4_netmask) {
      debug_log(0, "cfg->iface.ipv4_netmask cannot be empty\n");
      return false;
    }
  }

  {
    /* Validate srv_socket_cfg. */
    srv_sock_cfg *sock = &(cfg->sock);

    if (!sock->bind_addr) {
      debug_log(0, "cfg->sock.bind_addr cannot be empty\n");
      return false;
    }

    if (sock->type != SOCK_TCP && sock->type != SOCK_UDP) {
      debug_log(0, "cfg->sock.type must be \"tcp\" or \"udp\"");
      return false;
    }

    if (!sock->max_conn) {
      debug_log(0, "cfg->sock.max_conn must be at least 1\n");
      return false;
    }
  }


  {
    /* Validate other section. */
    if (!cfg->data_dir) {
      debug_log(0, "cfg->data_dir cannot be empty\n");
      return false;
    }
  }

  return true;
}


/**
 * @return void
 */
void 
tvpn_srv_version_info()
{
  printf("Version: %s\n", TEAVPN_SERVER_VERSION);
}

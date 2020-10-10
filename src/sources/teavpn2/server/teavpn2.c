
#include <teavpn2/server/common.h>
#include <teavpn2/server/sock/tcp.h>

inline static bool
tvpn_server_config_validate(server_cfg *config);

/**
 * @param server_cfg *config
 * @return int
 */
int
tvpn_server_run(server_cfg *config)
{
  int ret = 1;

  if (!tvpn_server_config_validate(config)) {
    goto ret;
  }

  switch (config->sock.type) {
    case SOCK_TCP:
      ret = tvpn_server_tcp_run(config);
      break;

    case SOCK_UDP:
      debug_log(0, "UDP socket is not supported yet!\n");
      break;

    default:
      debug_log(0, "Invalid socket type %d\n", config->sock.type);
      break;
  }

  ret:
  return ret;
}

/**
 * @param server_cfg *config
 * @return int
 */
inline static bool
tvpn_server_config_validate(server_cfg *config)
{
  debug_log(4, "Validating server config...");

  {
    /* Validate server_iface_cfg. */
    server_iface_cfg *iface = &(config->iface);

    if (!iface->dev) {
      debug_log(0, "config->iface.dev cannot be empty\n");
      return false;
    }

    if (!iface->ipv4) {
      debug_log(0, "config->iface.ipv4 cannot be empty\n");
      return false;
    }

    if (!iface->ipv4_netmask) {
      debug_log(0, "config->iface.ipv4_netmask cannot be empty\n");
      return false;
    }
  }

  {
    /* Validate server_socket_cfg. */
    server_socket_cfg *sock = &(config->sock);

    if (!sock->bind_addr) {
      debug_log(0, "config->sock.bind_addr cannot be empty\n");
      return false;
    }

    if (sock->type != SOCK_TCP && sock->type != SOCK_UDP) {
      debug_log(0, "config->sock.type must be \"tcp\" or \"udp\"");
      return false;
    }

    if (!sock->max_conn) {
      debug_log(0, "config->sock.max_conn must be at least 1\n");
      return false;
    }
  }


  {
    /* Validate other section. */
    if (!config->data_dir) {
      debug_log(0, "config->data_dir cannot be empty\n");
      return false;
    }
  }

  return true;
}


#include <teavpn2/client/common.h>
#include <teavpn2/client/sock/tcp.h>


inline static bool
tvpn_client_config_validate(client_cfg *config);


int
tvpn_client_run(client_cfg *config)
{
  int ret = 1;

  debug_log(4, "Validating client config...");
  if (!tvpn_client_config_validate(config)) {
    goto ret;
  }

  switch (config->sock.type) {
    case SOCK_TCP:
      ret = tvpn_client_tcp_run(config);
      goto ret;

    case SOCK_UDP:
      debug_log(0, "UDP socket is not supported yet!");
      goto ret;

    default:
      debug_log(0, "Invalid socket type %d", config->sock.type);
      goto ret;
  }


  ret:
  return ret;
}


inline static bool
tvpn_client_config_validate(client_cfg *config)
{
  {
    /* Validate client_iface_cfg. */
    client_iface_cfg *iface = &(config->iface);

    if (!iface->dev) {
      debug_log(0, "config->iface.dev cannot be empty");
      return false;
    }
  }

  {
    /* Validate client_socket_cfg. */
    client_socket_cfg *sock = &(config->sock);

    if (!sock->server_addr) {
      debug_log(0, "config->sock.server_addr cannot be empty");
      return false;
    }

    if (sock->type != SOCK_TCP && sock->type != SOCK_UDP) {
      debug_log(0, "config->sock.type must be \"tcp\" or \"udp\"");
      return false;
    }

  }


  {
    /* Validate other section. */
    if (!config->data_dir) {
      debug_log(0, "config->data_dir cannot be empty");
      return false;
    }
  }


  {
    /* Validate auth section. */
    client_auth_cfg *auth = &(config->auth);

    if (!auth->username) {
      debug_log(0, "config->auth.username cannot be empty");
      return false;
    }

    if (!auth->password) {
      debug_log(0, "config->auth.password cannot be empty");
      return false;
    }

    if (!auth->secret_key) {
      debug_log(0, "config->auth.secret_key cannot be empty");
      return false;
    }
  }

  return true;
}

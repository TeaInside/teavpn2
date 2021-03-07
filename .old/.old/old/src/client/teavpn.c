
#include <unistd.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/client/socket.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>

static bool validate_config(teavpn_client_config *config);

/**
 * @param teavpn_client_config *config
 * @return int
 */
int teavpn_client_run(teavpn_client_config *config)
{
if (!validate_config(config)) {
    return 1;
  }

  int ret = 1;
  iface_info iinfo;

  debug_log(2, "Allocating teavpn interface...");
  iinfo.tun_fd = teavpn_iface_allocate(config->iface.dev);
  if (iinfo.tun_fd < 0) {
    return 1; /* No need to close tun_fd, since failed to create. */
  }

  switch (config->socket_type) {
    case teavpn_sock_tcp:
      ret = teavpn_client_tcp_run(&iinfo, config);
      break;

    case teavpn_sock_udp:
      /* TODO: Make VPN be able to use UDP socket. */
      break;

    default:
      error_log("Invalid socket type");
      return 1;
      break;
  }

close:
  /* Close tun_fd. */
  close(iinfo.tun_fd);
  return ret;
}


/**
 * @param teavpn_client_config *config
 * @return bool
 */
static bool validate_config(teavpn_client_config *config)
{
  /**
   * Check data dir.
   */
  debug_log(5, "Checking server_addr...");
  if (config->socket.server_addr == NULL) {
    error_log("Server address cannot be empty!");
    return false;
  }

  return true;
}
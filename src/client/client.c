
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <teavpn/client/common.h>

inline static bool teavpn_validate_config(client_config *config);

/**
 * @param client_state *config
 * @return int
 */
int teavpn_client_run(client_config *config)
{
  client_state state;

  debug_log(5, "Validating config...");
  if (!teavpn_validate_config(config)) {
    return 1;
  }


  debug_log(5, "Allocating virtual interface...");
  if ((state.iface_fd = teavpn_iface_allocate(config->net.dev)) < 0) {
    return 1;
  }

  debug_log(5, "Virtual interface successfully created: \"%s\"", config->net.dev);

  switch (config->sock_type) {
    case TEAVPN_SOCK_TCP:
      return teavpn_client_tcp_run(&state);

    case TEAVPN_SOCK_UDP:
      return teavpn_client_udp_run(&state);

    default:
      error_log("Invalid sock_type: %d", config->sock_type);
      return 1;
  }
}

/**
 * @param client_state *config
 * @return bool
 */
inline static bool teavpn_validate_config(client_config *config)
{
  /*
   * Socket communication configuration.
   */
  assert((config->sock_type == TEAVPN_SOCK_TCP)
      || (config->sock_type == TEAVPN_SOCK_UDP));

  /*
   * Virtual network interface configuration.
   */
  assert(config->net.dev != NULL);

  if (config->server_addr == NULL) {
    error_log("server_addr cannot be empty!");
    return false;
  }

  if (config->server_port == 0) {
    error_log("server_port cannot be empty!");
    return false;
  }

  return true;
}

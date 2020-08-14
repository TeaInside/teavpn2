
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <teavpn/server/common.h>

inline static bool teavpn_validate_config(server_config *config);

/**
 * @param server_config *config
 * @return int
 */
int teavpn_server_run(server_config *config)
{
  server_state state;

  debug_log(5, "Validating config...");
  if (!teavpn_validate_config(config)) {
    return 1;
  }


  debug_log(5, "Allocating virtual interface...");
  if ((state.iface_fd = teavpn_iface_allocate(config->net.dev)) < 0) {
    return 1;
  }

  debug_log(5, "Virtual interface successfully created: \"%s\"", config->net.dev);

  if (inet_pton(AF_INET, config->net.inet4, &(state.inet4)) < 0) {
    perror("inet_pton");
    error_log("Error converting state.inet4: %s", config->net.inet4);
    return 1;
  }

  if (inet_pton(AF_INET, config->net.inet4_bcmask, &(state.inet4)) < 0) {
    perror("inet_pton");
    error_log("Error converting state.inet4_bcmask: %s", config->net.inet4_bcmask);
    return 1;
  }

  switch (config->sock_type) {
    case TEAVPN_SOCK_TCP:
      return teavpn_server_tcp_run(&state);

    case TEAVPN_SOCK_UDP:
      return teavpn_server_udp_run(&state);

    default:
      error_log("Invalid sock_type: %d", config->sock_type);
      return 1;
  }
}

/**
 * @param server_config *config
 * @return bool
 */
inline static bool teavpn_validate_config(server_config *config)
{
  /*
   * Socket communication configuration.
   */
  assert(config->bind_addr != NULL);
  assert((config->sock_type == TEAVPN_SOCK_TCP)
      || (config->sock_type == TEAVPN_SOCK_UDP));

  /*
   * Virtual network interface configuration.
   */
  assert(config->net.dev != NULL);


  if (config->data_dir == NULL) {
    error_log("data_dir cannot be empty!");
    return false;
  }

  if (config->net.inet4 == NULL) {
    error_log("inet4 cannot be empty!");
    return false;
  }

  if (config->net.inet4_bcmask == NULL) {
    error_log("inet4_bcmask cannot be empty!");
    return false;
  }

  return true;
}

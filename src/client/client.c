
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <teavpn/client/common.h>

#ifndef DEBUG_CONFIG_VALUES
#define DEBUG_CONFIG_VALUES 1
#endif

inline static bool teavpn_validate_config(client_config *config);

/**
 * @param client_state *config
 * @return int
 */
int teavpn_client_run(client_config *config)
{
  int ret;
  client_state state;

  state.config = config;

  if (config->config_file != NULL) {

    debug_log(5, "Loading config file: \"%s\"...", config->config_file);

    if (!teavpn_server_config_parser(config->config_file, config)) {
      return 1;
    }
  }

#if DEBUG_CONFIG_VALUES
  #define CFG_MACRO(FORMAT, VALUE) debug_log(0, #VALUE " = " FORMAT, VALUE)

  CFG_MACRO("%s", config->config_file);

  CFG_MACRO("%s", config->server_addr);
  CFG_MACRO("%d", config->server_port);
  CFG_MACRO("%d", config->sock_type);

  CFG_MACRO("%s", config->username);
  CFG_MACRO("%s", config->password);

  #undef CFG_MACRO
#endif


  debug_log(5, "Validating config...");
  if (!teavpn_validate_config(config)) {
    return 1;
  }

  debug_log(5, "Allocating virtual interface...");
  if ((state.iface_fd = teavpn_iface_allocate(state->net.dev)) < 0) {
    return 1;
  }

  debug_log(5, "Virtual interface successfully created: \"%s\"", state->net.dev);

  switch (state->sock_type) {
    case TEAVPN_SOCK_TCP:
      ret = teavpn_client_tcp_run(&state);
      break;

    case TEAVPN_SOCK_UDP:
      ret = teavpn_client_udp_run(&state);
      break;

    default:
      error_log("Invalid sock_type: %d", config->sock_type);
      ret = 1;
      break;
  }

  close(state.iface_fd);

  return ret;
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

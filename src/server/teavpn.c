
#include <stdio.h>

#include <teavpn2/server/iface.h>
#include <teavpn2/server/common.h>

static bool validate_config(teavpn_server_config *config);

/**
 * @param teavpn_server_config *config
 * @return int
 */
int teavpn_server_run(teavpn_server_config *config)
{
  if (!validate_config(config)) {
    return 1;
  }

  int tun_fd;

  tun_fd = teavpn_iface_allocate(config->iface.dev);
  if (tun_fd < 0) {
    return 1;
  }

  if (!tun_init_iface()) {

  }

  return 0;
}

/**
 * @param teavpn_server_config *config
 * @return bool
 */
static bool validate_config(teavpn_server_config *config)
{
  /**
   * Check data dir.
   */
  debug_log(5, "Checking data_dir...");
  if (config->data_dir == NULL) {
    error_log("Data dir cannot be empty!");
    return 1;
  }
}

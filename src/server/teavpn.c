
#include <stdio.h>
#include <teavpn2/server/common.h>

static bool validate_config(teavpn_server_config *config);

int teavpn_server_run(teavpn_server_config *config)
{
  if (!validate_config(config)) {
    return 1;
  }

}

static bool validate_config(teavpn_server_config *config)
{
  /**
   * Check data dir.
   */
  if (config->data_dir == NULL) {
    printf("Data dir cannot be empty!\n");
    return 1;
  }
}

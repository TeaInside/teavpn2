
#include <stdio.h>
#include <teavpn2/client/debugger.h>

/**
 * @param teavpn_client_config *config
 * @return void
 */
void print_client_config(teavpn_client_config *config)
{
  #define DPRINT(A, B) \
    printf("  "#A" = "B"\n", A)

  printf("===== Config Debug Info =====\n");
  DPRINT(config->iface.dev, "\"%s\"");
  DPRINT(config->iface.mtu, "%d");
  DPRINT(config->iface.inet4, "\"%s\"");
  DPRINT(config->iface.inet4_bcmask, "\"%s\"");

  DPRINT(config->socket_type, "%d");
  DPRINT(config->socket.server_addr, "\"%s\"");
  DPRINT(config->socket.server_port, "%d");

  DPRINT(config->auth.username, "\"%s\"");
  DPRINT(config->auth.password, "\"%s\"");

  printf("================================\n");
  fflush(stdout);
}


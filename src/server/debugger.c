
#include <stdio.h>
#include <teavpn2/server/debugger.h>

void print_server_config(teavpn_server_config *config)
{
  #define DPRINT(A, B) \
    printf(#A" = "B"\n", A);

  DPRINT(config->iface.dev, "%p")
  DPRINT(config->iface.mtu, "%d")
}

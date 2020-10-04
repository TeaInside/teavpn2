
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <teavpn2/client/common.h>

#define IFACE_CMD(CMD, ...)            \
  sprintf(cmd, CMD, __VA_ARGS__);      \
  debug_log(2, "Executing: %s", cmd);  \
  if (system(cmd)) {                   \
    return -1;                         \
  }

int client_tun_iface_up(client_iface_cfg *iface)
{

  return 0;
}

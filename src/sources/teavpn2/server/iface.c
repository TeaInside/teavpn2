
#include <teavpn2/server/common.h>

#define IFACE_CMD(CMD, ...)            \
  sprintf(cmd, CMD, __VA_ARGS__);      \
  debug_log(2, "Executing: %s", cmd);  \
  if (system(cmd)) {                   \
    return -1;                         \
  }

int tun_iface_up(server_iface_cfg *iface)
{
  char
    cmd[256],
    dev[16],
    ipv4[sizeof("xxx.xxx.xxx.xxx/xx")],
    ipv4_bcmask[sizeof("xxx.xxx.xxx.xxx")];

  escapeshellarg(dev, iface->dev);
  escapeshellarg(ipv4, iface->ipv4);
  escapeshellarg(ipv4_bcmask, iface->ipv4_bcmask);

  IFACE_CMD("/sbin/ip link set dev %s up mtu %d", dev, iface->mtu);
  IFACE_CMD("/sbin/ip addr add dev %s %s broadcast %s", dev, ipv4, ipv4_bcmask);

  return 0;
}

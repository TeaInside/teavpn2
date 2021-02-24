
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
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

bool
client_tun_iface_up(client_iface_cfg *iface)
{
  char dev[16];
  char cmd[256];
  char ipv4[sizeof("xxx.xxx.xxx.xxx/xx") + 2];
  char ipv4_network[sizeof("xxx.xxx.xxx.xxx/xx") + 2];
  char ipv4_broadcast[sizeof("xxx.xxx.xxx.xxx/xx") + 2];
  char ipv4_tmp_data[sizeof("xxx.xxx.xxx.xxx/xx")];

  uint8_t cidr;
  __be32 _ipv4;
  __be32 _ipv4_network;
  __be32 _ipv4_netmask;
  __be32 _ipv4_netmask_sc;
  __be32 _ipv4_broadcast;


  /* Convert netmask from chars to big endian integer. */
  if (!inet_pton(AF_INET, iface->ipv4_netmask, &_ipv4_netmask)) {
    debug_log(0, "Error: Invalid ipv4_netmask: \"%s\"", iface->ipv4_netmask);
    return false;
  }

  /* Convert netmask from big endian integer to CIDR. */
  _ipv4_netmask_sc = _ipv4_netmask;
  cidr = 0;
  while (_ipv4_netmask_sc) {
    cidr++;
    _ipv4_netmask_sc >>= 1;
  }

  /* Convert IPv4 from chars to big endian integer. */
  if (!inet_pton(AF_INET, iface->ipv4, &_ipv4)) {
    debug_log(0, "Error: Invalid ipv4: \"%s\"", iface->ipv4);
    return false;
  }
  /* Add CIDR to IPv4. */
  sprintf(&(iface->ipv4[strlen(iface->ipv4)]), "/%d", cidr);

  /*
   * A bitwise AND between IP address and netmask
   * will give the network address.
   */
  _ipv4_network   = (_ipv4 & _ipv4_netmask);


  /*
   * A bitwise OR between network address and inverted
   * netmask will give the broadcast address.
   */
  _ipv4_broadcast = _ipv4_network | (~_ipv4_netmask);


  /* Convert network address from big endian integer to chars. */
  if (!inet_ntop(AF_INET, &_ipv4_network, ipv4_tmp_data, sizeof(ipv4_tmp_data))) {
    debug_log(0, "Error: Invalid _ipv4_network: \"%x\"", _ipv4_network);
    return false;
  }
  /* Add CIDR to network address. */
  sprintf(&(ipv4_tmp_data[strlen(ipv4_tmp_data)]), "/%d", cidr);
  /* Escape the network address. */
  escapeshellarg(ipv4_network, ipv4_tmp_data);


  /* Convert broadcast address from big endian integer to chars. */
  if (!inet_ntop(AF_INET, &_ipv4_broadcast, ipv4_tmp_data, sizeof(ipv4_tmp_data))) {
    debug_log(0, "Error: Invalid _ipv4_broadcast: \"%x\"", _ipv4_broadcast);
    return false;
  }
  /* Escape the broadcast address. */
  escapeshellarg(ipv4_broadcast, ipv4_tmp_data);


  escapeshellarg(dev, iface->dev);
  escapeshellarg(ipv4, iface->ipv4);

  IFACE_CMD("/sbin/ip link set dev %s up mtu %d", dev, iface->mtu);
  IFACE_CMD("/sbin/ip addr add dev %s %s broadcast %s", dev, ipv4, ipv4_broadcast);


  // {
  //   char *ptr = strchr(iface->ipv4, '/');
  //   if (*ptr) {
  //     *ptr = '\0';
  //     escapeshellarg(ipv4, iface->ipv4);
  //   }
  // }

  // IFACE_CMD(
  //   "/sbin/ip route add %s dev %s proto kernel scope link src %s",
  //   ipv4_network,
  //   dev, ipv4
  // );

  return true;
}



/**
 * Initialize network interface for TeaVPN server.
 *
 * @param server_config *config
 * @return bool
 */
bool teavpn_server_iface_init(struct teavpn_iface *iface)
{
  register size_t arena_pos = 0;
  register size_t l;
  char cmd[256], _arena[256],
    *dev,
    *inet4,
    *inet4_bc,
    *arena = _arena;

  dev = escape_sh(arena, iface->dev, strlen(iface->dev));
  arena += strlen(dev) + 1;
  inet4 = escape_sh(arena, iface->inet4, strlen(iface->inet4));
  arena += strlen(inet4) + 1;
  inet4_bc = escape_sh(arena, iface->inet4_bcmask, strlen(iface->inet4_bcmask));

  debug_log(5, "dev: %s", dev);
  debug_log(5, "inet4: %s", inet4);
  debug_log(5, "inet4_bc: %s", inet4_bc);

  #define EXEC_CMD(CMD, ...) \
    sprintf(cmd, CMD, ##__VA_ARGS__); \
    debug_log(0, "Executing: %s", cmd); \
    if (system(cmd)) { \
      return false; \
    }

  EXEC_CMD("/sbin/ip link set dev %s up mtu %d", dev, iface->mtu);
  EXEC_CMD("/sbin/ip addr add dev %s %s broadcast %s", dev, inet4, inet4_bc);
  EXEC_CMD("/usr/sbin/iptables -t nat -I POSTROUTING -s %s ! -d %s -j MASQUERADE", inet4, inet4);

  return true;
  #undef EXEC_CMD
}


/**
 * Remove network interface configuration.
 *
 * @param server_config *config
 * @return bool
 */
bool teavpn_server_iface_clean_up(struct teavpn_iface *iface)
{
  register size_t arena_pos = 0;
  register size_t l;
  char cmd[256], _arena[256],
    *dev,
    *inet4,
    *inet4_bc,
    *arena = _arena;

  dev = escape_sh(arena, iface->dev, strlen(iface->dev));
  arena += strlen(dev) + 1;
  inet4 = escape_sh(arena, iface->inet4, strlen(iface->inet4));
  arena += strlen(inet4) + 1;
  inet4_bc = escape_sh(arena, iface->inet4_bcmask, strlen(iface->inet4_bcmask));

  debug_log(5, "dev: %s", dev);
  debug_log(5, "inet4: %s", inet4);
  debug_log(5, "inet4_bc: %s", inet4_bc);

  #define EXEC_CMD(CMD, ...) \
    sprintf(cmd, CMD, ##__VA_ARGS__); \
    debug_log(0, "Executing: %s", cmd); \
    if (system(cmd)) { \
      return false; \
    }

  EXEC_CMD("/usr/sbin/iptables -t nat -D POSTROUTING -s %s ! -d %s -j MASQUERADE", inet4, inet4);
  EXEC_CMD("/sbin/ip addr delete dev %s %s broadcast %s", dev, inet4, inet4_bc);

  return true;
  #undef EXEC_CMD
}

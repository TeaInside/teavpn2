
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>

#include <teavpn2/server/common.h>

inline static bool iface_init(tcp_state * __restrict__ state);

/**
 * @param server_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int tvpn_server_tcp_run(server_cfg *config)
{
  int ret = 1;
  tcp_state state;

  state.config    = config;
  state.channels  =
    (tcp_channel *)malloc(sizeof(tcp_channel) * config->sock.max_conn);

  debug_log(4, "Allocating virtual network interface...");
  if (!iface_init(&state)) {
    goto ret;
  }




  ret:
  return ret;
}

/**
 * @param  tcp_state * __restrict__ state
 * @return bool
 */
inline static bool iface_init(tcp_state * __restrict__ state)
{
  server_iface_cfg *iface  = &(state->config->iface);

  tun_alloc(iface->dev, IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE);




  return true;
}

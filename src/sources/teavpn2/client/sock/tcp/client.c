
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

#include <teavpn2/client/common.h>

#define PIPE_BUF (16)

inline static void tvpn_client_tcp_signal_handler(int signal);
inline static bool tvpn_client_tcp_iface_init(client_tcp_state * __restrict__ state);
inline static bool tvpn_client_tcp_sock_init(client_tcp_state * __restrict__ state);
inline static bool tvpn_client_tcp_socket_setup(int fd);

static client_tcp_state *g_state = NULL;

/**
 * @param client_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int tvpn_client_tcp_run(client_cfg *config)
{
  int                   ret = 1;
  int                   pipe_fd[2] = {-1, -1};
  client_tcp_state      state;
  struct pollfd         fds[2];
  nfds_t                nfds;
  int                   ptimeout;


  state.net_fd = -1;
  state.stop   = false;
  g_state      = &state;
  state.config = config;

  debug_log(2, "Allocating virtual network interface...");
  if (!tvpn_client_tcp_iface_init(&state)) {
    goto ret;
  }

  ret:

  return ret;
}


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_client_tcp_iface_init(client_tcp_state * __restrict__ state)
{

}

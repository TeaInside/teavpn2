
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/global/data_struct.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>

inline static bool teavpn_client_tcp_init(client_tcp_mstate *mstate);
inline static bool teavpn_client_tcp_socket_setup(int net_fd);

/**
 * @param teavpn_client_config *config
 * @return bool
 */
__attribute__((force_align_arg_pointer))
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *config)
{
  char buf_pipe[8];
  int ret = 0;
  client_tcp_mstate mstate;

  bzero(&mstate, sizeof(mstate));

  mstate.tun_fd = iinfo->tun_fd;
  mstate.config = config;
  mstate.iinfo = iinfo;

  /**
   * Init TCP socket.
   */
  if (!teavpn_client_tcp_init(&mstate)) {
    ret = 1;
    goto close_conn;
  }




close_conn:
  if (mstate.net_fd != -1) {
    close(mstate.net_fd);
  }
  return ret;
}

/**
 * @param client_tcp_mstate *mstate
 * @return bool
 */
inline static bool teavpn_client_tcp_init(client_tcp_mstate *mstate)
{
  /**
   * Create TCP socket.
   */
  debug_log(0, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (mstate->net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(0, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(0, "Setting up socket file descriptor...");
  if (!teavpn_client_tcp_socket_setup(mstate->net_fd)) {
    perror("Error setsockopt()");
    return false;
  }
  debug_log(0, "Socket file descriptor set up successfully");

  /**
   * Prepare server address and port.
   */
  bzero(&(mstate->server_addr), sizeof(mstate->server_addr));
  mstate->server_addr.sin_family = AF_INET;
  mstate->server_addr.sin_port = htons(mstate->config->socket.server_port);
  mstate->server_addr.sin_addr.s_addr = inet_addr(mstate->config->socket.server_addr);

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Connecting to %s:%d...", mstate->config->socket.server_addr, mstate->config->socket.server_port);

  if (connect(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(struct sockaddr_in)) < 0) {
    perror("Error on connect");
    return false;
  }

  debug_log(0, "Connection established!");

  return true;
}

/**
 * @param int net_fd
 * @return bool
 */
inline static bool teavpn_client_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }

  return true;
}
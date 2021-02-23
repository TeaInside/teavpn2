
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/poll.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/global/data_struct.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>

static inline bool teavpn_client_tcp_init(client_tcp_mstate *mstate);
static inline bool teavpn_client_tcp_socket_setup(int net_fd);

/**
 * @param teavpn_client_config *config
 * @return bool
 */
__attribute__((force_align_arg_pointer))
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *config)
{
  int ret = 0;
  client_tcp_mstate mstate;

  /* Initialize mstate values. */
  bzero(&mstate, sizeof(client_tcp_mstate));
  mstate.iinfo = iinfo;
  mstate.config = config;
  mstate.tun_fd = iinfo->tun_fd;
  config->mstate = (void *)&mstate;

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
static inline bool teavpn_client_tcp_init(client_tcp_mstate *mstate)
{
  /**
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(0, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (mstate->net_fd < 0) {
    perror("Socket creation failed");
    error_log("Cannot create TCP socket");
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

  {
    int rc = 0;
    nfds_t nfds = 1;
    struct pollfd fds[1];

poll_t:
    fds[0].fd = mstate->net_fd;
    fds[0].events = POLLIN;

    while (rc == 0) {
      rc = poll(fds, nfds, 10);
    }

    /**
     * Connect to the server.
     */
    if (connect(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(struct sockaddr_in)) < 0) {
      if (errno == EINPROGRESS) {
        goto poll_t;
      }
      perror("Error on connect");
      return false;
    }

    debug_log(0, "Connection established!");
  }

  return true;
}


/**
 * @param int net_fd
 * @return bool
 */
static inline bool teavpn_client_tcp_socket_setup(int net_fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN) \
    if (setsockopt(net_fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) { \
      perror("setsockopt()"); \
      error_log("setsockopt() error"); \
      return false; \
    }

  SET_SOCK_OPT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}

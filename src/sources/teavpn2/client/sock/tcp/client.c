
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
inline static bool tvpn_client_tcp_auth(client_tcp_state * __restrict__ state);
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
  state.tun_fd = -1;
  state.stop   = false;
  g_state      = &state;
  state.config = config;

  debug_log(2, "Allocating virtual network interface...");
  if (!tvpn_client_tcp_iface_init(&state)) {
    goto ret;
  }

  debug_log(2, "Initializing pipe...");
  if (pipe(pipe_fd) < -1) {
    goto ret;
  }

  debug_log(2, "Initializing TCP socket...");
  if (!tvpn_client_tcp_sock_init(&state)) {
    goto ret;
  }

  debug_log(2, "Authenticating...");
  if (!tvpn_client_tcp_auth(&state)) {
    goto ret;
  }

  ret:

  /* Close TUN/TAP fd. */
  if (state.tun_fd != -1) {
    debug_log(0, "Closing tun_fd -> (%d)...", state.tun_fd);
    close(state.tun_fd);
  }

  /* Close TCP socket. */
  if (state.net_fd != -1) {
    debug_log(0, "Closing net_fd -> (%d)...", state.net_fd);
    close(state.net_fd);
  }

  /* Close pipe */
  if (pipe_fd[0] != -1) {
    debug_log(0, "Closing pipe_fd[0] -> (%d)...", pipe_fd[0]);
    close(pipe_fd[0]);
  }
  if (pipe_fd[1] != -1) {
    debug_log(0, "Closing pipe_fd[1] -> (%d)...", pipe_fd[1]);
    close(pipe_fd[1]);
  }

  return ret;
}


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_client_tcp_iface_init(client_tcp_state * __restrict__ state)
{
  int               fd;
  client_cfg       *config   = state->config;
  client_iface_cfg *iface    = &(config->iface);


  debug_log(5, "Allocating tun_fd...");
  fd = tun_alloc(iface->dev, IFF_TAP);

  if (fd < 0) {
    printf("Cannot allocate virtual network interface");
    return false;
  }

  state->tun_fd = fd;

  return true;
}

/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_client_tcp_sock_init(client_tcp_state * __restrict__ state)
{
  int                  rv, fd       = -1;
  client_socket_cfg   *sock         = &(state->config->sock);
  socklen_t            addrlen      = sizeof(struct sockaddr_in);
  struct sockaddr_in   server_addr;

  /*
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(2, "Creating TCP socket...");
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    debug_log(0, "Socket creation failed: %s", strerror(errno));
    return false;
  }
  debug_log(5, "TCP socket created successfully!");


  /*
   * Setup TCP socket.
   */
  debug_log(2, "Setting up socket file descriptor...");
  if (!tvpn_client_tcp_socket_setup(fd)) {
    return false;
  }
  debug_log(5, "Socket file descriptor set up successfully!");


  /*
   * Prepare server bind address data.
   */
  bzero(&server_addr, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(sock->server_port);
  server_addr.sin_addr.s_addr = inet_addr(sock->server_addr);

  debug_log(0, "Connecting to %s:%d...", sock->server_addr, sock->server_port);

  still_connecting:
  if (connect(fd, (struct sockaddr *)&server_addr, addrlen) < 0) {

    if (errno == EINPROGRESS) {
      goto still_connecting;
    }

    debug_log(0, "Error connect(): %s", strerror(errno));
    return false;
  }


  debug_log(0, "Connection established!");

  /*
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  signal(SIGINT, tvpn_client_tcp_signal_handler);
  signal(SIGHUP, tvpn_client_tcp_signal_handler);
  signal(SIGTERM, tvpn_client_tcp_signal_handler);  

  state->net_fd = fd;
  return true;

  err:
  if (fd != -1) {
    debug_log(0, "Closing socket descriptor...");
    close(fd);
  }
  return false;
}

/**
 * @param  int fd
 * @return bool
 */
inline static bool tvpn_client_tcp_socket_setup(int fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN)            \
    if (setsockopt(fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {     \
      debug_log(0, "Error setsockopt: %s", strerror(errno));      \
      return false;                                               \
    }

  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_client_tcp_auth(client_tcp_state * __restrict__ state)
{

}


/**
 * @param  int signal
 * @return void
 */
inline static void tvpn_client_tcp_signal_handler(int signal)
{
  (void)signal;
  g_state->stop = true;
}


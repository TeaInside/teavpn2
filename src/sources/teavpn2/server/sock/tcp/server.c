
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

inline static void tvpn_server_tcp_signal_handler(int signal);
inline static bool tvpn_server_tcp_iface_init(tcp_state * __restrict__ state);
inline static bool tvpn_server_tcp_sock_init(tcp_state * __restrict__ state);
inline static bool tvpn_server_tcp_sock_init(tcp_state * __restrict__ state);
inline static void tvpn_server_tcp_accept(tcp_state * __restrict__ state);
inline static bool tvpn_server_tcp_socket_setup(int fd);

inline static void tvpn_server_init_channel(tcp_channel *chan);
inline static void tvpn_server_init_channels(tcp_channel *channels, uint16_t max_conn);

static tcp_state *g_state = NULL;

/**
 * @param server_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int tvpn_server_tcp_run(server_cfg *config)
{
  const uint16_t max_conn   = config->sock.max_conn;
  int            ret        = 1;
  int            pipe_fd[2] = {-1, -1};
  tcp_state      state;
  struct pollfd  fds[2];
  nfds_t         nfds;
  int            ptimeout;

  state.net_fd = -1;
  state.stop   = false;
  g_state      = &state;

  {
    state.config      = config;
    state.channels    = (tcp_channel *)malloc(sizeof(tcp_channel) * max_conn);

    debug_log(2, "Initializing client channels (max_conn: %d)...", max_conn);
    tvpn_server_init_channels(state.channels, max_conn);
  }

  debug_log(2, "Allocating virtual network interface...");
  if (!tvpn_server_tcp_iface_init(&state)) {
    goto ret;
  }

  debug_log(2, "Initializing pipe...");
  if (pipe(pipe_fd) < -1) {
    goto ret;
  }

  debug_log(2, "Initializing TCP socket...");
  if (!tvpn_server_tcp_sock_init(&state)) {
    goto ret;
  }


  /* Add TCP socket fd to fds. */
  fds[0].fd     = state.net_fd;
  fds[0].events = POLLIN;

  /* Add pipe fd to fds. */
  fds[1].fd     = pipe_fd[0];
  fds[1].events = POLLIN;

  nfds          = 2;
  ptimeout      = 3000;


  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);


    /* Poll reached timeout. */
    if (rv == 0) {
      goto end_loop;
    }

    /* Accept new client. */
    if (fds[0].revents == POLLIN) {
      tvpn_server_tcp_accept(&state);
    }

    end_loop:
    if (state.stop) {
      ret = 0;
      break;
    }
  }

  ret:
  {
    /* Close tun fd(s). */
    tcp_channel *channels = state.channels;
    for (uint16_t i = 0; i < max_conn; ++i) {
      int the_fd = channels[i].tun_fd;
      if (the_fd != -1) {
        debug_log(0, "Closing tun_fd -> (%d)", the_fd);
        close(the_fd);
      }
    }

    free(channels);
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
 * @param  tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_server_tcp_iface_init(tcp_state * __restrict__ state)
{
  server_cfg       *config   = state->config;
  tcp_channel      *channels = state->channels;
  server_iface_cfg *iface    = &(config->iface);
  uint16_t          max_conn = config->sock.max_conn;
  uint16_t          i        = 0;

  for (i = 0; i < max_conn; i++) {
    channels[i].tun_fd = -1;
  }

  for (i = 0; i < max_conn; i++) {
    int fd;

    debug_log(5, "Allocating tun_fd, (seq:%d)...", i);
    fd = tun_alloc(iface->dev, IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE);
    if (fd < 0) {
      printf("Cannot allocate virtual network interface: i = %d\n", i);
      goto err;
    }

    channels[i].tun_fd = fd;
  }

  tun_iface_up(iface);

  return true;

  err:

  /* Close opened file descriptor. */
  if (i) {
    debug_log(5, "Closing opened tun_fd(s)...");
    while (i--) {
      debug_log(5, "Closing tun_fd %d...", i);
      close(channels[i].tun_fd);
      channels[i].tun_fd = -1;
    }
  }

  return false;
}


/** 
 * @param tcp_channel *channels
 * @param uint16_t     max_conn
 * @return void
 */
inline static void tvpn_server_init_channels(tcp_channel *channels, uint16_t max_conn)
{
  while (max_conn--) {
    tvpn_server_init_channel(&(channels[max_conn]));
  }
}


/** 
 * @param tcp_channel *chan
 * @return void
 */
inline static void tvpn_server_init_channel(tcp_channel *chan)
{
  chan->is_used     = false;
  chan->authorized  = false;
  chan->cli_fd      = -1;
  chan->recv_count  = 0;
  chan->send_count  = 0;
  chan->ipv4        = 0x00000000;
  chan->username    = NULL;
}


/**
 * @param  tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_server_tcp_sock_init(tcp_state * __restrict__ state)
{
  int                  rv, fd = -1;
  server_socket_cfg   *sock         = &(state->config->sock);
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
  if (!tvpn_server_tcp_socket_setup(fd)) {
    return false;
  }
  debug_log(5, "Socket file descriptor set up successfully!");


  /*
   * Prepare server bind address data.
   */
  bzero(&server_addr, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(sock->bind_port);
  server_addr.sin_addr.s_addr = inet_addr(sock->bind_addr);


  /*
   * Bind socket to address.
   */
  rv = bind(fd, (struct sockaddr *)&(server_addr), sizeof(struct sockaddr_in));
  if (rv < 0) {
    debug_log(0, "Bind error: %s", strerror(errno));
    goto err;
  }


  /*
   * Listen socket.
   */
  if (listen(fd, sock->backlog) < 0) {
    debug_log(0, "Listen error: %s", strerror(errno));
    goto err;
  }

  debug_log(0, "Listening on %s:%d...", sock->bind_addr, sock->bind_port);

  /*
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  signal(SIGINT, tvpn_server_tcp_signal_handler);
  signal(SIGHUP, tvpn_server_tcp_signal_handler);
  signal(SIGTERM, tvpn_server_tcp_signal_handler);  

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
inline static bool tvpn_server_tcp_socket_setup(int fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN)            \
    if (setsockopt(fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {     \
      debug_log(0, "Error setsockopt: %s", strerror(errno));      \
      return false;                                               \
    }

  SET_SOCK_OPT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}

/**
 * @param tcp_state * __restrict__ state 
 * @return void
 */
inline static void tvpn_server_tcp_accept(tcp_state * __restrict__ state)
{

}

/**
 * @param int signal
 * @return void
 */
inline static void tvpn_server_tcp_signal_handler(int signal)
{
  (void)signal;
  g_state->stop = true;
}

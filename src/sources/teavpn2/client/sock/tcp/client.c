
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
inline static void tvpn_client_tcp_recv_handler(client_tcp_state *__restrict__ state);

inline static bool tvpn_client_tcp_handle_auth_ok(
  client_tcp_state *__restrict__ state,
  size_t data_size
);

inline static void tvpn_client_tcp_handle_data(
  client_tcp_state *__restrict__ state,
  size_t data_size
);


inline static void tvpn_server_tcp_tun_handler(
  client_tcp_state *__restrict__ state
);

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
  struct pollfd         fds[3];
  nfds_t                nfds;
  int                   ptimeout;


  state.net_fd     = -1;
  state.tun_fd     = -1;
  state.authorized = false;
  state.stop       = false;
  g_state          = &state;
  state.config     = config;
  state.recv_size  = 0;
  state.send_size  = 0;

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

  /* Add TCP socket fd to fds. */
  fds[0].fd     = state.net_fd;
  fds[0].events = POLLIN;

  /* Add TUN/TAP fd to fds. */
  fds[1].fd     = state.tun_fd;
  fds[1].events = POLLIN;

  /* Add pipe fd to fds. */
  fds[2].fd     = pipe_fd[0];
  fds[2].events = POLLIN;

  nfds     = 3;
  ptimeout = 3000;

  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);

    /* Poll reached timeout. */
    if (unlikely(rv == 0)) {
      debug_log(5, "poll() timeout, no action required.");
      goto end_loop;
    }

    /* Reading from net. */
    if (likely(fds[0].revents == POLLIN)) {
      tvpn_client_tcp_recv_handler(&state);
    }

    /* Reading from TUN/TAP. */
    if (likely(fds[1].revents == POLLIN)) {
      tvpn_server_tcp_tun_handler(&state);
    }

    /* Pipe interrupt. */
    if (unlikely(fds[2].revents == POLLIN)) {
      char buf[PIPE_BUF];
      if (read(fds[2].fd, buf, PIPE_BUF) < 0) {
        debug_log(0, "Error reading from pipe_fd[0]: %s", strerror(errno));
      }
    }

    end_loop:
    if (state.stop) {
      break;
    }
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
  fd = tun_alloc(iface->dev, IFF_TUN);

  if (fd < 0) {
    debug_log(0, "Cannot allocate virtual network interface");
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
  int                  fd           = -1;
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

    register int _errno = errno;

    if (_errno == EINPROGRESS || _errno == EALREADY) {
      goto still_connecting;
    }

    debug_log(0, "Error connect(): %s", strerror(_errno));
    goto err;
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
  int rv;
  client_cfg *config     = state->config;
  client_auth_cfg *auth  = &(config->auth);
  client_pkt *cli_pkt    = (client_pkt *)state->send_buff;
  auth_pkt   *auth_p     = (auth_pkt   *)cli_pkt->data;

  cli_pkt->type          = CLI_PKT_AUTH;
  cli_pkt->size          = sizeof(auth_pkt);
  auth_p->username_len   = strlen(auth->username);
  auth_p->password_len   = strlen(auth->password);
  strncpy(auth_p->username, auth->username, sizeof(auth_p->username) - 1);
  strncpy(auth_p->password, auth->password, sizeof(auth_p->password) - 1);

  rv = send(
    state->net_fd,
    cli_pkt,
    CLI_IDENT_PKT_SIZE + sizeof(auth_pkt),
    MSG_DONTWAIT
  );

  if (rv < 0) {
    debug_log(0, "Error send(): %s", strerror(errno));
  }

  return true;
}


/**
 * @param client_tcp_state *__restrict__ state
 * @return void
 */
inline static void tvpn_client_tcp_recv_handler(client_tcp_state *__restrict__ state)
{
  register ssize_t  ret;
  register size_t   lrecv_size = state->recv_size;

  ret = recv(state->net_fd, &(state->recv_buff[lrecv_size]), TCP_RECV_BUFFER, 0);

  if (likely(ret < 0)) {
    if (errno != EWOULDBLOCK) {
      /* An error occured that causes disconnection. */
      debug_log(0, "Error recv(): %s", strerror(errno));
      state->stop = true;
    }
    return;
  } else if (unlikely(ret == 0)) {
    /* Server disconnected. */
    debug_log(0, "Disconnected from the server.");
    state->stop = true;
    return;
  }

  debug_log(5, "recv(): %ld bytes from net_fd.", ret);

  server_pkt *srv_pkt  = (server_pkt *)&(state->recv_buff[0]);
  state->recv_size    += (size_t)ret;

  if (likely(state->recv_size >= SRV_IDENT_PKT_SIZE)) {
    size_t data_size = state->recv_size - CLI_IDENT_PKT_SIZE;

    switch (srv_pkt->type) {

      /*
       * In this branch table, the callee is responsible to
       * zero the recv_size if it has finished its job.
       */
      case SRV_PKT_PING:
        break;

      case SRV_PKT_AUTH_OK:
        debug_log(2, "Got SRV_PKT_AUTH_OK!");
        debug_log(0, "Authentication success!");
        if (!tvpn_client_tcp_handle_auth_ok(state, data_size)) {
          state->stop = true;
        }
        break;

      case SRV_PKT_AUTH_REJECT:
        debug_log(2, "Got SRV_PKT_AUTH_REJECT!");
        debug_log(0, "Authentication failed!");
        state->stop = true;
        break;

      case SRV_PKT_DATA:
        if (state->authorized) {
          tvpn_client_tcp_handle_data(state, data_size);
        } else {
          debug_log(4, "Got invalid SRV_PKT_DATA");
        }
        break;

      case SRV_PKT_DISCONNECT:
        debug_log(2, "Got SRV_PKT_DISCONNECT!");
        debug_log(0, "Disconnecting...");
        state->stop = true;
        break;

      default:
        debug_log(3, "Got invalid packet type: %d", srv_pkt->type);
        break;
    }
  }

}

/**
 * @param  client_tcp_state *__restrict__ state
 * @param  size_t                         data_size
 * @return bool
 */
inline static bool tvpn_client_tcp_handle_auth_ok(
  client_tcp_state *__restrict__ state,
  size_t data_size
)
{
  client_cfg       *config   = state->config;
  client_iface_cfg *iface    = &(config->iface);
  server_pkt       *srv_pkt  = (server_pkt *)state->recv_buff;

  if (data_size < srv_pkt->size) {
    debug_log(4, "Pending auth ok data...");
    /* Data has not been received completely. */
    return true;
  }

  {
    char ipv4[sizeof("xxx.xxx.xxx.xxx/xx")];
    char ipv4_netmask[sizeof("xxx.xxx.xxx.xxx")];

    iface->ipv4            = ipv4;
    iface->ipv4_netmask    = ipv4_netmask;
    srv_auth_res *auth_res = (srv_auth_res *)srv_pkt->data;

    inet_ntop(AF_INET, &(auth_res->ipv4), ipv4, sizeof(ipv4));
    inet_ntop(AF_INET, &(auth_res->ipv4_netmask), ipv4_netmask, sizeof(ipv4_netmask));

    if (!client_tun_iface_up(iface)) {
      debug_log(0, "client_tun_iface_up failed!");
      return false;
    }
  }

  state->authorized = true;
  return true;
}


/**
 * @param  client_tcp_state *__restrict__ state
 * @param  size_t                         data_size
 * @return void
 */
inline static void tvpn_client_tcp_handle_data(
  client_tcp_state *__restrict__ state,
  size_t data_size
)
{
  server_pkt *srv_pkt  = (server_pkt *)state->recv_buff;

  if (data_size < srv_pkt->size) {
    /* Data has not been received completely. */
    return;
  }

  {
    ssize_t rv;

    rv = write(state->tun_fd, srv_pkt->data, srv_pkt->size);
    if (rv < 0) {
      debug_log(0, "Error write to tun: %s", strerror(errno));
      return;
    }
    debug_log(5, "Write to tun_fd %ld bytes", rv);
  }
}


/**
 * @param  client_tcp_state *__restrict__ state
 * @return void
 */
inline static void tvpn_server_tcp_tun_handler(
  client_tcp_state *__restrict__ state
)
{
  ssize_t     rv;
  server_pkt  *srv_pkt = (server_pkt *)state->send_buff;
  srv_pkt->type        = SRV_PKT_DATA;

  rv = read(state->tun_fd, srv_pkt->data, SERVER_DATA_SIZE);
  if (rv < 0) {
    debug_log(0, "Error read from tun: %s", strerror(errno));
    return;
  }
  debug_log(5, "Read from tun_fd %ld bytes", rv);

  srv_pkt->size = (size_t)rv;

  rv = send(state->net_fd, srv_pkt, SRV_IDENT_PKT_SIZE + srv_pkt->size, MSG_DONTWAIT);
  if (rv < 0) {
    debug_log(0, "Error send(): %s", strerror(errno));
    return;
  }
  debug_log(5, "Send to net_fd %ld bytes", rv);
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


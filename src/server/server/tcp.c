
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <teavpn/server/tcp.h>

inline static bool teavpn_server_tcp_socket_setup(int sock_fd);
inline static bool teavpn_server_tcp_init(server_tcp_state *tcp_state);
inline static bool teavpn_server_tcp_accept(server_tcp_state *tcp_state);
inline static int32_t teavpn_server_tcp_chan_observe(server_tcp_state *tcp_state);
inline static void teavpn_traverse_channels(server_tcp_state *tcp_state);
inline static void teavpn_serve_client(server_tcp_state *tcp_state, tcp_channel *chan);

/**
 * @param server_state *state
 * @return int
 */
__attribute__((force_align_arg_pointer))
int teavpn_server_tcp_run(server_state *state)
{
  int ret = 0, rc;
  server_config *config = state->config;
  server_tcp_state tcp_state;

  tcp_state.server_state = state;
  tcp_state.stop_all     = false;
  tcp_state.online_chan  = 0;

  /* Init TCP socket. */
  if (!teavpn_server_tcp_init(&tcp_state)) {
    ret = 1;
    goto close_conn;
  }

  tcp_state.channels = (tcp_channel *)malloc(
    config->max_connections * sizeof(tcp_channel));

  memset(tcp_state.channels, 0, config->max_connections * sizeof(tcp_channel));

  tcp_state.fds = (struct pollfd *)malloc(
    config->max_connections * sizeof(struct pollfd));

  /* Init pipe. */
  if (pipe(tcp_state.pipe_fd) == -1) {
    perror("pipe()");
    goto close_conn;
  }


  /* Main TCP socket fd, for accepting new connection. */
  tcp_state.fds[0].fd = tcp_state.sock_fd;
  tcp_state.fds[0].events = POLLIN;

  /* Virtual network interface fd. */
  tcp_state.fds[1].fd = state->iface_fd;
  tcp_state.fds[1].events = POLLIN;

  /* Pipe fd for interrupt. */
  tcp_state.fds[2].fd = tcp_state.pipe_fd[0];
  tcp_state.fds[2].events = POLLIN;

  tcp_state.nfds = 3;
  tcp_state.timeout = 3000;

  /* Event Loop. */
  while (true) {

    rc = poll(tcp_state.fds, tcp_state.nfds, tcp_state.timeout);

    /* Poll reached timeout. */
    if (rc == 0) {
      goto end_loop;
    }

    /* Accept new client. */
    if (tcp_state.fds[0].revents == POLLIN) {
      teavpn_server_tcp_accept(&tcp_state);
    }

    /* Handle server's tunnel interface data. */
    if (tcp_state.fds[1].revents == POLLIN) {
      // teavpn_server_tcp_handle_iface_data(&tcp_state);
    }

    /* Handle pipe. */
    if (tcp_state.fds[2].revents == POLLIN) {
      goto end_loop;
    }

    teavpn_traverse_channels(&tcp_state);


end_loop:
    if (tcp_state.stop_all) {
      debug_log(0, "Got stop_all signal");
      goto close_conn;
    }
  }

close_conn:
  if (tcp_state.sock_fd != -1) {
    debug_log(2, "Closing sock_fd...");
    close(tcp_state.sock_fd);
  }

  if (tcp_state.pipe_fd[0] != -1) {
    debug_log(2, "Closing pipe_fd[0]...");
    close(tcp_state.pipe_fd[0]);
  }

  if (tcp_state.pipe_fd[1] != -1) {
    debug_log(2, "Closing pipe_fd[1]...");
    close(tcp_state.pipe_fd[1]);
  }

  /* Release heap. */
  free(tcp_state.fds);

  return ret;
}

/** 
 * @param server_tcp_state  *tcp_state
 * @return bool
 */
inline static bool teavpn_server_tcp_init(server_tcp_state *tcp_state)
{
  server_state  *state = tcp_state->server_state;
  server_config *config = state->config;

  /* Create TCP socket (SOCK_STREAM). */
  debug_log(0, "Creating TCP socket...");

  tcp_state->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (tcp_state->sock_fd < 0) {
    perror("Socket creation failed");
    error_log("Cannot create TCP socket");
    return false;
  }

  debug_log(0, "TCP socket created successfully");


  /* Setup TCP socket. */
  debug_log(0, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(tcp_state->sock_fd)) {
    return false;
  }
  debug_log(0, "Socket file descriptor set up successfully");


  /* Prepare server bind address data. */
  bzero(&(tcp_state->server_addr), sizeof(struct sockaddr_in));
  tcp_state->server_addr.sin_family = AF_INET;
  tcp_state->server_addr.sin_port = htons(config->bind_port);
  tcp_state->server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);


  /* Bind socket to address. */
  if (
      bind(
        tcp_state->sock_fd,
        (struct sockaddr *)&(tcp_state->server_addr),
        sizeof(tcp_state->server_addr)
      ) < 0
    ) {
    perror("Bind failed");
    error_log("Bind socket failed");
    return false;
  }


  /* Listen socket. */
  if (listen(tcp_state->sock_fd, config->backlog) < 0) {
    perror("Listen failed");
    error_log("Listen socket failed");
    return false;
  }


  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Listening on %s:%d...", config->bind_addr, config->bind_port);

  return true;
}


/**
 * @param int sock_fd
 * @return bool
 */
inline static bool teavpn_server_tcp_socket_setup(int sock_fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN)              \
    if (setsockopt(sock_fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {  \
      perror("setsockopt()");                                       \
      error_log("setsockopt() error");                              \
      return false;                                                 \
    }

  SET_SOCK_OPT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}

/**
 * @param server_tcp_state *tcp_state
 * @return bool
 */
inline static bool teavpn_server_tcp_accept(server_tcp_state *tcp_state)
{
  int32_t i;
  int acc_fd;
  tcp_channel *chan;
  struct sockaddr_in saddr;
  bool drop = false, ret  = true;
  socklen_t rlen = sizeof(struct sockaddr_in);

  debug_log(5, "Acceping new connection...");
  i = teavpn_server_tcp_chan_observe(tcp_state);

  if (i == -1) {
    /* Drop connection if the channel array is full. */
    debug_log(5, "Channel array is full, dropping new connection...");
    drop = true;
  } else {
    debug_log(5, "New connection channel index: %d", i);
    chan = &(tcp_state->channels[(uint16_t)i]);
  }

  acc_fd = accept(tcp_state->sock_fd, (struct sockaddr *)&(saddr), &rlen);

  if (acc_fd == -1) {
    perror("accept()");
    error_log("Error: Unable to accept new connection.");
    ret = false;
    goto ret;
  }

  if (drop) {
    /* Channel is full, sorry can't accept more. */
    close(acc_fd);
    ret = false;
    goto ret;
  }


  /*
   * Welcome to the channel, the client will go to authentication
   * step after it reaches here.
   */
  debug_log(5, "Registering new connection to poll event...");
  chan->seq   = 0;
  memset(&(chan->auth), 0, sizeof(chan->auth));
  chan->inet4 = 0;
  chan->inet4_bcmask = 0;
  chan->recvi  = 0;
  chan->ifacei = 0;

  tcp_state->fds[tcp_state->nfds].fd = acc_fd;
  tcp_state->fds[tcp_state->nfds].events = POLLIN;
  chan->fds = &(tcp_state->fds[tcp_state->nfds]);
  tcp_state->nfds++;

ret:
  return ret;
}

/**
 * @param server_tcp_state *tcp_state
 * @return int32_t
 */
inline static int32_t teavpn_server_tcp_chan_observe(server_tcp_state *tcp_state)
{
  register server_state  *state    = tcp_state->server_state;
  register server_config *config   = state->config;
  register tcp_channel   *channels = tcp_state->channels;

  register uint16_t i   = 0;
  register uint16_t max = config->max_connections;

  for (i = 0; i < max; ++i) {
    if (!channels[i].used) {
      channels[i].used = true;
      return i;
    }
  }

  return -1;
}

/**
 * @param server_tcp_state *tcp_state
 * @return void
 */
inline static void teavpn_traverse_channels(server_tcp_state *tcp_state)
{
  register server_state  *state    = tcp_state->server_state;
  register server_config *config   = state->config;
  register tcp_channel   *channels = tcp_state->channels;
  register tcp_channel   *chan;

  register uint16_t i   = 0;
  register uint16_t max = config->max_connections;

  for (i = 0; i < max; ++i) {
    chan = &(channels[i]);

    if (!chan->used) {
      /* Skip empty channel. */
      continue;
    }

    if (chan->fds->revents == POLLIN) {
      teavpn_serve_client(tcp_state, chan);
    }
  }
}

/**
 * @param server_tcp_state  *tcp_state
 * @param tcp_channel       *chan
 * @return void
 */
inline static void teavpn_serve_client(server_tcp_state *tcp_state, tcp_channel *chan)
{
  int recv_ret;
  void *recv_buf = (void *)(&(chan->recv_buf[chan->recvi]));

  recv_ret = recv(chan->fds->fd, recv_buf, RECV_BUF_SIZE, MSG_DONTWAIT);
  if (recv_ret == -1) {
    if (EWOULDBLOCK != errno) {
      perror("recv()");
    }
  }

  chan->recvi += (uint16_t)recv_ret;

  debug_log(5, "Receiving %d bytes", recv_ret);
}

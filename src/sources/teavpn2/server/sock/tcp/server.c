
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

#define PIPE_BUF (16)

inline static void tvpn_server_tcp_signal_handler(int signal);
inline static bool tvpn_server_tcp_iface_init(server_tcp_state * __restrict__ state);
inline static bool tvpn_server_tcp_sock_init(server_tcp_state * __restrict__ state);
inline static void tvpn_server_tcp_accept(server_tcp_state * __restrict__ state);
inline static bool tvpn_server_tcp_socket_setup(int fd);

inline static void tvpn_server_init_channel(tcp_channel *chan);
inline static void tvpn_server_init_channels(tcp_channel *channels, uint16_t max_conn);

inline static int32_t tvpn_server_tcp_chan_get(tcp_channel *channels, uint16_t max_conn);

inline static void tvpn_server_tcp_accept_and_drop(int net_fd);

inline static void *tvpn_server_tcp_worker_thread(void *_chan);
inline static void tvpn_server_tcp_recv_handler(tcp_channel *chan, server_tcp_state *state);

inline static void tvpn_server_tcp_auth_hander(
  tcp_channel *chan,
  server_tcp_state *state,
  size_t data_size,
  size_t lrecv_size
);

static server_tcp_state *g_state = NULL;

/**
 * @param server_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int tvpn_server_tcp_run(server_cfg *config)
{
  const uint16_t        max_conn   = config->sock.max_conn;
  int                   ret        = 1;
  int                   pipe_fd[2] = {-1, -1};
  server_tcp_state      state;
  struct pollfd         fds[2];
  nfds_t                nfds;
  int                   ptimeout;

  state.net_fd      = -1;
  state.stop        = false;
  g_state           = &state;
  state.config      = config;
  state.channels    = (tcp_channel *)malloc(sizeof(tcp_channel) * max_conn);

  debug_log(2, "Initializing client channels (max_conn: %d)...", max_conn);
  tvpn_server_init_channels(state.channels, max_conn);

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

    /* Accept new client. */
    if (fds[1].revents == POLLIN) {
      char buf[PIPE_BUF];
      if (read(pipe_fd[0], buf, PIPE_BUF) < 0) {
        debug_log(0, "Error reading from pipe_fd[0]: %s", strerror(errno));
      }
    }

    end_loop:
    debug_log(5, "rv = %d", rv);
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

      if (channels[i].is_used) {
        debug_log(0, "Closing connected client(s)...");
        pthread_kill(channels[i].thread, SIGTERM);
        pthread_mutex_lock(&(channels[i].ht_mutex));
      }

      if (the_fd != -1) {
        debug_log(0, "Closing tun_fd -> (%d)", the_fd);
        close(the_fd);
      }

      if (channels[i].is_used) {
        pthread_mutex_unlock(&(channels[i].ht_mutex));
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
 * @param  server_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_server_tcp_iface_init(server_tcp_state * __restrict__ state)
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
    fd = tun_alloc(iface->dev, IFF_TAP | IFF_MULTI_QUEUE);
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
  chan->is_used      = false;
  chan->is_connected = false;
  chan->authorized   = false;
  chan->cli_fd       = -1;
  chan->recv_count   = 0;
  chan->send_count   = 0;
  chan->ipv4         = 0x00000000;
  chan->username     = NULL;
  chan->recv_size    = 0;
  chan->send_size    = 0;
}


/**
 * @param  server_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool tvpn_server_tcp_sock_init(server_tcp_state * __restrict__ state)
{
  int                  rv, fd       = -1;
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
 * @param  tcp_channels *channels
 * @param  uint16_t      max_conn
 * @return int32_t
 */
inline static int32_t tvpn_server_tcp_chan_get(tcp_channel *channels, uint16_t max_conn)
{
  for (register uint16_t i = 0; i < max_conn; i++) {
    if (!channels[i].is_used) {
      return (uint32_t)i;
    }
  }

  return -1;
}


/**
 * @param  server_tcp_state * __restrict__ state 
 * @return void
 */
inline static void tvpn_server_tcp_accept(server_tcp_state * __restrict__ state)
{
  tcp_channel     *chan;
  tcp_channel     *channels   = state->channels;
  const uint16_t   max_conn   = state->config->sock.max_conn;
  int              net_fd     = state->net_fd;
  int32_t          free_index;

  free_index = tvpn_server_tcp_chan_get(channels, max_conn);
  if (free_index == -1) {
    debug_log(2, "Channel is full, cannot handle more client");
    tvpn_server_tcp_accept_and_drop(net_fd);
    return;
  }

  {
    int                cli_fd;
    struct sockaddr_in addr;
    socklen_t          rlen = sizeof(struct sockaddr_in);

    cli_fd = accept(net_fd, (struct sockaddr *)&addr, &rlen);
    if (cli_fd < 0) {
      debug_log(0, "Error accept(): %s", strerror(errno));
      return;
    }

    chan = &(channels[free_index]);
    tvpn_server_init_channel(chan);
    chan->is_used      = true;
    chan->is_connected = true;
    chan->cli_fd       = cli_fd;

    if (pthread_mutex_init(&(chan->ht_mutex), NULL) < 0) {
      debug_log(0, "phtread_mutex_init error: %s", strerror(errno));
      return;
    }

    pthread_create(
      &(chan->thread),
      NULL,
      tvpn_server_tcp_worker_thread,
      (void *)chan
    );
    pthread_detach(chan->thread);
  }
}


/**
 * @param  int net_fd
 * @return void
 */
inline static void tvpn_server_tcp_accept_and_drop(int net_fd)
{
  int                cli_fd;
  struct sockaddr_in addr;
  socklen_t          rlen = sizeof(struct sockaddr_in);

  cli_fd = accept(net_fd, (struct sockaddr *)&addr, &rlen);
  if (cli_fd < 0) {
    debug_log(0, "Error accept(): %s", strerror(errno));
    return;
  }
  close(cli_fd);
}


/**
 * @param  void *_chan
 * @return void *
 */
inline static void *tvpn_server_tcp_worker_thread(void *_chan)
{
  struct pollfd               fds[2];
  register server_tcp_state   *state   = g_state;
  register tcp_channel        *chan    = (tcp_channel *)_chan;
  register nfds_t             nfds     = 2;
  const int                   ptimeout = 3000;

  /* TUN/TAP fd. */
  fds[0].fd     = chan->tun_fd;
  fds[0].events = POLLIN;

  /* Client socket fd. */
  fds[1].fd     = chan->cli_fd;
  fds[1].events = POLLIN;

  pthread_mutex_lock(&(chan->ht_mutex));
  tun_set_queue(chan->tun_fd, 1);

  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);

    /* Poll reached timeout. */
    if (unlikely(rv == 0)) {
      debug_log(5, "poll() timeout, no action required.");
      goto end_loop;
    } else if (likely(fds[0].revents == POLLIN)) {
      char buff[4096];
      debug_log(5, "Reading from tun... %d", read(fds[0].fd, buff, 4096));
    } else if (likely(fds[1].revents == POLLIN)) {
      tvpn_server_tcp_recv_handler(chan, state);
    }

    end_loop:
    debug_log(5, "cli rv = %d", rv);
    if ((state->stop) || (!chan->is_connected)) {
      debug_log(5, "Event loop ended!");
      break;
    }
  }

  close(chan->cli_fd);
  chan->is_used = false;
  tun_set_queue(chan->tun_fd, 0);
  pthread_mutex_unlock(&(chan->ht_mutex));

  return NULL;
}


/**
 * @param  tcp_channel       *chan
 * @param  server_tcp_state  *state
 * @return void
 */
inline static void tvpn_server_tcp_recv_handler(tcp_channel *chan, server_tcp_state *state)
{
  register ssize_t  ret;
  register size_t   lrecv_size = chan->recv_size;

  ret = recv(chan->cli_fd, &(chan->recv_buff[lrecv_size]), TCP_RECV_BUFFER, 0);

  if (likely(ret < 0)) {
    if (errno != EWOULDBLOCK) {
      /* An error occured that causes disconnection. */
      debug_log(0, "Error occured: %s", strerror(errno));
      chan->is_connected = false;
    }
    return;
  } else if (unlikely(ret == 0)) {
    /* Client disconnected. */
    debug_log(0, "Client disconnected");
    chan->is_connected = false;
    return;
  }

  client_pkt *cli_pkt  = (client_pkt *)&(chan->recv_buff[0]);
  chan->recv_size     += (size_t)ret;

  if (likely(chan->recv_size >= IDENTIFIER_PKT_SIZE)) {

    size_t data_size = chan->recv_size - IDENTIFIER_PKT_SIZE;

    switch (cli_pkt->type) {
      case TCP_PKT_PING:
        break;

      case TCP_PKT_AUTH:
        tvpn_server_tcp_auth_hander(chan, state, data_size, lrecv_size);
        break;

      case TCP_PKT_DATA:
        break;

      case TCP_PKT_DISCONNECT:
        break;

      default:
        break;
    }
  }

}


/**
 * @param  tcp_channel       *chan
 * @param  server_tcp_state  *state
 * @return void
 */
inline static void tvpn_server_tcp_auth_hander(
  tcp_channel *chan,
  server_tcp_state *state,
  size_t data_size,
  size_t lrecv_size
)
{

}


/**
 * @param  int signal
 * @return void
 */
inline static void tvpn_server_tcp_signal_handler(int signal)
{
  (void)signal;
  g_state->stop = true;
}

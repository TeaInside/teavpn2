
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
inline static void tvpn_server_tcp_recv_handler(
  tcp_channel * __restrict__ chan,
  server_tcp_state * __restrict__ state
);
inline static void tvpn_server_tcp_tun_handler(
  tcp_channel * __restrict__ chan,
  server_tcp_state * __restrict__ state
);

inline static void tvpn_client_tcp_handle_data(
  tcp_channel *__restrict__ chan,
  size_t data_size
);

inline static bool tvpn_server_tcp_auth_hander(
  tcp_channel *chan,
  server_tcp_state *state,
  size_t data_size,
  size_t lrecv_size
);

server_tcp_state *g_state = NULL;

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
    if (likely(rv == 0)) {
      goto end_loop;
    }

    /* Accept new client. */
    if (unlikely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_accept(&state);
    }

    /* Pipe interrupt. */
    if (unlikely(fds[1].revents == POLLIN)) {
      char buf[PIPE_BUF];
      if (read(pipe_fd[0], buf, PIPE_BUF) < 0) {
        debug_log(0, "Error reading from pipe_fd[0]: %s", strerror(errno));
      }
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
    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);
    if (fd < 0) {
      printf("Cannot allocate virtual network interface: i = %d\n", i);
      goto err;
    }
    tun_set_queue(fd, 0);

    channels[i].tun_fd = fd;
  }

  server_tun_iface_up(iface);

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

    memset(&addr, 0, sizeof(struct sockaddr_in));

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
    chan->addr         = addr;

    inet_ntop(
      AF_INET,
      &(addr.sin_addr.s_addr),
      chan->r_ip_src,
      sizeof(chan->r_ip_src)
    );

    // sprintf(
    //   chan->r_ip_src,
    //   "%d.%d.%d.%d",
    //   (addr.sin_addr.s_addr >> 0 ) & 0xff,
    //   (addr.sin_addr.s_addr >> 8 ) & 0xff,
    //   (addr.sin_addr.s_addr >> 16) & 0xff,
    //   (addr.sin_addr.s_addr >> 24) & 0xff
    // );

    chan->r_port_src   = ntohs(addr.sin_port);

    debug_log(1, "Accepting connection from %s:%d...", HP_CC(chan));

    if (pthread_mutex_init(&(chan->ht_mutex), NULL) < 0) {
      close(cli_fd);
      debug_log(0, "phtread_mutex_init error: %s", strerror(errno));
      debug_log(1, "Closing connection from %s:%d...", HP_CC(chan));
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
  if (tun_set_queue(chan->tun_fd, 1) < 0) {
    debug_log(0, "tun_set_queue(): %s", strerror(errno));
    goto close_conn;
  }

  memset(chan->recv_buff, 0, sizeof(chan->recv_buff));
  memset(chan->send_buff, 0, sizeof(chan->send_buff));

  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);

    /* Poll reached timeout. */
    if (unlikely(rv == 0)) {
      // debug_log(5, "poll() timeout, no action required.");
      goto end_loop;
    }

    if (likely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_tun_handler(chan, state);
    }

    if (likely(fds[1].revents == POLLIN)) {
      tvpn_server_tcp_recv_handler(chan, state);
    }

    end_loop:
    if ((state->stop) || (!chan->is_connected)) {
      debug_log(5, "Event loop ended!");
      break;
    }
  }

  close_conn:
  debug_log(1, "Closing connection from %s:%d...", HP_CC(chan));

  if (chan->cli_fd != -1) {
    close(chan->cli_fd);
  }
  chan->is_used = false;
  tun_set_queue(chan->tun_fd, 0);
  pthread_mutex_unlock(&(chan->ht_mutex));

  return NULL;
}


/**
 * @param  tcp_channel       * __restrict__ chan
 * @param  server_tcp_state  * __restrict__ state
 * @return void
 */
inline static void tvpn_server_tcp_recv_handler(
  tcp_channel * __restrict__ chan,
  server_tcp_state * __restrict__ state
)
{
  char x;
  register ssize_t  ret;
  register size_t   lrecv_size = chan->recv_size;
  register char     *buf       = &(chan->recv_buff[lrecv_size]);

  if (*buf) {
    x = *buf;
  }

  ret = recv(chan->cli_fd, buf, TCP_RECV_BUFFER, 0);

  if (likely(ret < 0)) {
    if (errno != EWOULDBLOCK) {
      /* An error occured that causes disconnection. */
      debug_log(0, "[%s:%d] Error recv(): %s %c", HP_CC(chan), strerror(errno), x);
      chan->is_connected = false;
    }
    return;
  } else if (unlikely(ret == 0)) {
    /* Client disconnected. */
    debug_log(0, "[%s:%d] Client disconnected", HP_CC(chan));
    chan->is_connected = false;
    return;
  }

  debug_log(5, "recv %ld bytes from cli_fd", ret);

  client_pkt *cli_pkt  = (client_pkt *)&(chan->recv_buff[0]);
  chan->recv_size     += (size_t)ret;

  if (likely(chan->recv_size >= CLI_IDENT_PKT_SIZE)) {

    size_t data_size = chan->recv_size - CLI_IDENT_PKT_SIZE;

    switch (cli_pkt->type) {

      /*
       * In this branch table, the callee is responsible to
       * zero the recv_size if it has finished its job.
       *
       * Not only zero the recv_table, the callee is also
       * responsible to zero the buffer, since it contains
       * the length of data. This length of data may be reused
       * if it is not zeroed.
       */

      case CLI_PKT_PING:
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        break;

      case CLI_PKT_AUTH:
        if (!tvpn_server_tcp_auth_hander(chan, state, data_size, lrecv_size)) {
          close(chan->cli_fd);
          chan->cli_fd       = -1;
          chan->is_connected = false;
        }
        break;

      case CLI_PKT_DATA:
        tvpn_client_tcp_handle_data(chan, data_size);
        break;

      case CLI_PKT_DISCONNECT:
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        break;

      default:
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        debug_log(3, "Got invalid packet type: %d", cli_pkt->type);
        break;
    }
  }

}


/**
 * @param tcp_channel       *__restrict__  chan
 * @param size_t                           data_size
 * @return bool
 */
inline static void tvpn_client_tcp_handle_data(
  tcp_channel *__restrict__ chan,
  size_t data_size
)
{
  client_pkt *cli_pkt = (client_pkt *)chan->recv_buff;

  if (data_size < cli_pkt->size) {
    /* Data has not been received completely. */
    return;
  }

  {
    ssize_t rv;

    rv = write(chan->tun_fd, cli_pkt->data, cli_pkt->size);
    if (rv < 0) {
      debug_log(0, "Error write to tun: %s", strerror(errno));
      goto ret;
    }
    debug_log(5, "Write to tun_fd %ld bytes", rv);
  }

  ret:
  cli_pkt->size   = 0;
  chan->recv_size = 0;
  return;
}


/**
 * @param tcp_channel       *__restrict__  chan
 * @param server_tcp_state                 *state
 * @param size_t                           data_size
 * @param size_t                           lrecv_size
 * @return bool
 */
inline static bool tvpn_server_tcp_auth_hander(
  tcp_channel *__restrict__ chan,
  server_tcp_state *state,
  size_t data_size,
  size_t lrecv_size
)
{
  bool ret;
  client_pkt *cli_pkt = (client_pkt *)chan->recv_buff;

  if (data_size < cli_pkt->size) {
    /* Data has not been received completely. */
    return true;
  }


  {
    ssize_t           rv;
    server_pkt        srv_pkt;
    client_auth_tmp   auth_tmp;
    uint8_t           data_size = 0;
    srv_auth_res      *auth_res = (srv_auth_res *)srv_pkt.data;
    auth_pkt          *auth_p   = (auth_pkt   *)cli_pkt->data;

    /* For string safety. */
    auth_p->username[254] = '\0';
    auth_p->password[254] = '\0';

    debug_log(2, "[%s:%d] Receiving auth data...", HP_CC(chan));
    debug_log(2, "[%s:%d] Username: \"%s\"", HP_CC(chan), auth_p->username);
    debug_log(2, "[%s:%d] Password: \"%s\"", HP_CC(chan), auth_p->password);

    if (tvpn_auth_tcp(auth_p, chan, &auth_tmp)) {
      chan->authorized = true;
      srv_pkt.type     = SRV_PKT_AUTH_OK;
      srv_pkt.size     = data_size;
      ret              = true;
      data_size        = sizeof(srv_auth_res);

      if (!inet_pton(AF_INET, auth_tmp.ipv4, &(auth_res->ipv4))) {
        debug_log(0, "[%s:%d] Error, invalid ipv4: \"%s\"",
          auth_tmp.ipv4);
        ret = false;
        goto ret;
      }

      if (!inet_pton(AF_INET, auth_tmp.ipv4_netmask, &(auth_res->ipv4_netmask))) {
        debug_log(0, "[%s:%d] Error, invalid ipv4_netmask: \"%s\"",
          auth_tmp.ipv4_netmask);
        ret = false;
        goto ret;
      }

    } else {
      srv_pkt.type     = SRV_PKT_AUTH_REJECT;
      srv_pkt.size     = 0;
      ret              = false;
    }

    rv = send(chan->cli_fd, &srv_pkt, SRV_IDENT_PKT_SIZE + data_size, MSG_DONTWAIT);
    if (rv < 0) {
      debug_log(0, "[%s:%d] Error send(): %s", HP_CC(chan), strerror(errno));
      ret = false;
      goto ret;
    }

  }

  ret:
  cli_pkt->size   = 0;
  chan->recv_size = 0;
  return ret;
}


/**
 * @param  tcp_channel       * __restrict__ chan
 * @param  server_tcp_state  * __restrict__ state
 * @return void
 */
inline static void tvpn_server_tcp_tun_handler(
  tcp_channel * __restrict__ chan,
  server_tcp_state * __restrict__ state
)
{
  ssize_t     rv;
  server_pkt  *srv_pkt = (server_pkt *)chan->send_buff;
  srv_pkt->type        = SRV_PKT_DATA;

  rv = read(chan->tun_fd, srv_pkt->data, DATA_SIZE);
  if (rv < 0) {
    debug_log(0, "Error read from tun: %s", strerror(errno));
    return;
  }
  debug_log(5, "Read from tun_fd %ld bytes", rv);

  srv_pkt->size = (size_t)rv;

  rv = send(chan->cli_fd, srv_pkt, SRV_IDENT_PKT_SIZE + srv_pkt->size, MSG_DONTWAIT);
  if (rv < 0) {
    debug_log(0, "[%s:%d] Error send(): %s", HP_CC(chan), strerror(errno));
    return;
  }
  debug_log(5, "Send to cli_fd %ld bytes", rv);
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



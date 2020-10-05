
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

inline static void
tvpn_server_tcp_init_channels(tcp_channel *__restrict__ channels,
                              uint16_t max_conn);

inline static void
tvpn_server_tcp_init_channel(tcp_channel *__restrict__ chan);

inline static bool
tvpn_server_tcp_init_iface(server_tcp_state *__restrict__ state);

inline static bool
tvpn_server_tcp_init_pipe(int *__restrict__ pipe_fd);

inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *__restrict__ state);

inline static bool
tvpn_server_tcp_socket_setup(int fd);

inline static void
tvpn_server_tcp_accept(server_tcp_state *__restrict__ state);

inline static int32_t
tvpn_server_tcp_chan_get(tcp_channel *__restrict__ channels,
                         uint16_t max_conn);

inline static void
tvpn_server_tcp_accept_and_drop(int net_fd);

inline static void *
tvpn_server_tcp_worker_thread(void *__restrict__ _chan);

inline static void
tvpn_server_tcp_tun_handler(tcp_channel *__restrict__ chan);

inline static void
tvpn_server_tcp_recv_handler(tcp_channel *__restrict__ chan);

inline static void
tvpn_server_tcp_auth_hander(tcp_channel *__restrict__ chan, size_t rdata_size);

inline static void
tvpn_client_tcp_handle_data(tcp_channel *__restrict__ chan, size_t rdata_size);

inline static void
tvpn_server_tcp_signal_handler(int signal);

server_tcp_state *g_state;

/**
 * @param server_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int
tvpn_server_tcp_run(server_cfg *config)
{
  server_tcp_state  state;
  int               ret        = 1; /* Exit code. */
  int               pipe_fd[2] = {-1, -1};
  int               ptimeout;
  struct pollfd     fds[2];
  nfds_t            nfds;
  const uint16_t    max_conn   = config->sock.max_conn;



  /* ================================================= */
  g_state        = &state;
  state.net_fd   = -1;
  state.stop     = false;
  state.config   = config;
  state.channels = (tcp_channel *)
                   malloc(sizeof(tcp_channel) * max_conn);

  tvpn_server_tcp_init_channels(state.channels, max_conn);
  /* ================================================= */


  if (!tvpn_server_tcp_init_iface(&state)) {
    goto ret;
  }

  if (!tvpn_server_tcp_init_pipe(pipe_fd)) {
    goto ret;
  }

  if (!tvpn_server_tcp_init_socket(&state)) {
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

  /* Poll event loop. */
  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);

    /* Poll reached timeout/interrupted. */
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
        debug_log(0, "Error reading from pipe_fd[0]: %s", 
          strerror(errno));
      }
    }

    end_loop:
    if (state.stop) {
      ret = 0;
      break;
    }
  }

  ret:

  return ret;
}


/**
 * @param tcp_channel *__restrict__ channels
 * @param uint16_t    max_conn
 * @return void
 */
inline static void
tvpn_server_tcp_init_channels(tcp_channel *__restrict__ channels,
                              uint16_t max_conn)
{
  for (register uint16_t i = 0; i < max_conn; i++) {
    tvpn_server_tcp_init_channel(&(channels[i]));
  }
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_init_channel(tcp_channel *__restrict__ chan)
{
  memset(chan, 0, sizeof(tcp_channel));
  chan->cli_fd = -1;
  chan->tun_fd = -1;
}


/**
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_iface(server_tcp_state *__restrict__ state)
{
  register server_cfg        *config   = state->config;
  register tcp_channel       *channels = state->channels;
  register server_iface_cfg  *iface    = &(config->iface);
  register uint16_t          i         = 0;
  const uint16_t             max_conn  = config->sock.max_conn;


  debug_log(2, "Allocating virtual network interface...");

  for (i = 0; i < max_conn; i++) {
    register int fd;

    debug_log(5, "Allocating tun_fd, (seq:%d)...", i);

    fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);
    if (fd < 0) {
      debug_log(0, 
        "Cannot allocate virtual network interface: i = %d\n", i);
      goto err;
    }

    if (fd_set_nonblock(fd) < 0) {
      debug_log(0, "Error fd_set_nonblock(): %s", strerror(errno));
      close(fd);
      goto err;
    }

    if (tun_set_queue(fd, false) < 0) {
      debug_log(0, "Error tun_set_queue(): %s", strerror(errno));
      close(fd);
      goto err;
    }

    channels[i].tun_fd = fd;
  }

  return server_tun_iface_up(iface);

  err:
  /* Close opened file descriptors. */
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
 * @param  int *__restrict__ pipe_fd
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_pipe(int *__restrict__ pipe_fd)
{
  register bool ret;

  debug_log(2, "Initializing pipe...");

  ret = !(pipe(pipe_fd) < -1);

  if (!ret) {
    debug_log(0, "Error pipe(): %s", strerror(errno));
  }

  return ret;
}


/**
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static bool
tvpn_server_tcp_init_socket(server_tcp_state *__restrict__ state)
{
  register int                rv;
  register int                fd;
  register server_socket_cfg  *sock = &(state->config->sock);

  struct sockaddr_in          server_addr;

  /*
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(2, "Creating TCP socket...");
  fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    debug_log(0, "Error socket(): %s", strerror(errno));
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
  memset(&server_addr, 0, sizeof(struct sockaddr_in));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(sock->bind_port);
  server_addr.sin_addr.s_addr = inet_addr(sock->bind_addr);


  /*
   * Bind socket to address.
   */
  rv = bind(fd, (struct sockaddr *)&(server_addr), sizeof(struct sockaddr_in));
  if (rv < 0) {
    debug_log(0, "Error bind(): %s", strerror(errno));
    goto err;
  }


  /*
   * Listen socket.
   */
  if (listen(fd, sock->backlog) < 0) {
    debug_log(0, "Error listen(): %s", strerror(errno));
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
 * @param int fd
 * @return bool
 */
bool
tvpn_server_tcp_socket_setup(int fd)
{
  int opt_1 = 1;

  #define SET_XT(LEVEL, OPTNAME, OPTVAL, OPTLEN)               \
    if (setsockopt(fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) {  \
      debug_log(0, "Error setsockopt(): %s", strerror(errno)); \
      return false;                                            \
    }

  SET_XT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_XT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_XT
}


/**
 * @param tcp_channel *__restrict__ channels
 * @param uint16_t max_conn
 * @return int32_t
 */
inline static int32_t
tvpn_server_tcp_chan_get(tcp_channel *__restrict__ channels,
                         uint16_t max_conn)
{
  while (max_conn--) {
    if (!channels[max_conn].is_used) {
      return (int32_t)max_conn;
    }
  }

  return -1;
}


/**
 * @param  int net_fd
 * @return void
 */
inline static void
tvpn_server_tcp_accept_and_drop(int net_fd)
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
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static void
tvpn_server_tcp_accept(server_tcp_state *__restrict__ state)
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

  chan = &(channels[free_index]);

  {
    int       cli_fd;
    socklen_t rlen = sizeof(struct sockaddr_in);

    memset(&(chan->addr), 0, sizeof(struct sockaddr_in));

    cli_fd = accept(net_fd, (struct sockaddr *)&(chan->addr), &rlen);
    if (cli_fd < 0) {
      debug_log(0, "Error accept(): %s", strerror(errno));
      return;
    }

    chan->is_used      = true;
    chan->is_connected = true;
    chan->authorized   = false;
    chan->recv_count   = 0;
    chan->send_count   = 0;
    chan->ipv4         = 0x00000000;
    chan->ipv4_netmask = 0x00000000;
    chan->username     = NULL;
    chan->recv_size    = 0;
    chan->send_size    = 0;
    chan->cli_fd       = cli_fd;

    memset(chan->recv_buff, 0, sizeof(chan->recv_buff));
    memset(chan->send_buff, 0, sizeof(chan->send_buff));

    inet_ntop(AF_INET, &(chan->addr.sin_addr.s_addr),
      chan->r_ip_src, sizeof(chan->r_ip_src));

    chan->r_port_src   = ntohs(chan->addr.sin_port);

    debug_log(1, "Accepting connection from %s:%d...", HP_CC(chan));

    if (pthread_mutex_init(&(chan->ht_mutex), NULL) < 0) {
      close(cli_fd);
      debug_log(0, "phtread_mutex_init error: %s", strerror(errno));
      debug_log(1, "Closing connection from %s:%d...", HP_CC(chan));
      return;
    }

    pthread_create(&(chan->thread), NULL,
                   tvpn_server_tcp_worker_thread, (void *)chan);
    pthread_detach(chan->thread);
  }
}


/**
 * @param void *__restrict__ _chan
 * @return bool
 */
inline static void *
tvpn_server_tcp_worker_thread(void *__restrict__ _chan)
{
  struct pollfd              fds[2];
  register server_tcp_state  *state   = g_state;
  register tcp_channel       *chan    = (tcp_channel *)_chan;
  register nfds_t            nfds     = 2;
  const int                  ptimeout = 3000;

  /* TUN/TAP fd. */
  fds[0].fd     = chan->tun_fd;
  fds[0].events = POLLIN;

  /* Client socket fd. */
  fds[1].fd     = chan->cli_fd;
  fds[1].events = POLLIN;

  pthread_mutex_lock(&(chan->ht_mutex));

  if (tun_set_queue(chan->tun_fd, true) < 0) {
    debug_log(0, "tun_set_queue(): %s", strerror(errno));
    goto close_conn;
  }

  memset(chan->recv_buff, 0, sizeof(chan->recv_buff));
  memset(chan->send_buff, 0, sizeof(chan->send_buff));

  while (true) {
    int rv;

    rv = poll(fds, nfds, ptimeout);

    /* Poll reached timeout/interrupted. */
    if (unlikely(rv == 0)) {
      goto end_loop;
    }

    if (likely(fds[0].revents == POLLIN)) {
      tvpn_server_tcp_tun_handler(chan);
    }

    if (likely(fds[1].revents == POLLIN)) {
      tvpn_server_tcp_recv_handler(chan);
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
  tun_set_queue(chan->tun_fd, false);
  pthread_mutex_unlock(&(chan->ht_mutex));

  return NULL;
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_tun_handler(tcp_channel *__restrict__ chan)
{
  ssize_t       rv;
  server_pkt    *srv_pkt = (server_pkt *)chan->send_buff;

  rv = read(chan->tun_fd, srv_pkt->data, DATA_SIZE);
  if (rv < 0) {
    debug_log(0, "Error read from tun: %s", strerror(errno));
    return;
  }
  debug_log(5, "Read from tun_fd %ld bytes", rv);

  srv_pkt->type = SRV_PKT_DATA;
  srv_pkt->size = (size_t)rv;

  rv = send(chan->cli_fd, srv_pkt,
            SR_IDENT_SIZ + srv_pkt->size, MSG_DONTWAIT);

  if (rv < 0) {
    debug_log(0, "[%s:%d] Error send(): %s", HP_CC(chan), strerror(errno));
    return;
  }

  debug_log(5, "Send to cli_fd %ld bytes", rv);
}


/**
 * @param tcp_channel *__restrict__ chan
 * @return void
 */
inline static void
tvpn_server_tcp_recv_handler(tcp_channel *__restrict__ chan)
{
  size_t      rdata_size; /* Received data size. */
  ssize_t     ret;
  size_t      crz;
  size_t      lrecv      = chan->recv_size;
  char        *rbuf      = chan->recv_buff;
  client_pkt  *cli_pkt   = (client_pkt *)rbuf;

  if (unlikely(lrecv >= CL_IDENT_SIZ)) {
    rdata_size = lrecv - CL_IDENT_SIZ;
    crz        = cli_pkt->size - rdata_size;
  } else {
    crz        = TCP_RECV_BUFFER;
  }

  ret = recv(chan->cli_fd, &(rbuf[lrecv]), crz, 0);

  if (likely(ret < 0)) {

    if (errno != EWOULDBLOCK) {
      /* An error occured that causes disconnection. */
      debug_log(0, "[%s:%d] Error recv(): %s", HP_CC(chan), strerror(errno));
      chan->is_connected = false;
    }
    return;

  } else
  if (unlikely(ret == 0)) {

    debug_log(0, "[%s:%d] Client disconnected", HP_CC(chan));
    chan->is_connected = false;
    return;

  }

  debug_log(5, "Received %ld bytes from cli_fd", ret);

  chan->recv_count++;
  chan->recv_size += (size_t)ret;

  if (likely(chan->recv_size >= CL_IDENT_SIZ)) {

    rdata_size = chan->recv_size - CL_IDENT_SIZ;

    switch (cli_pkt->type) {
      /*
       * In this branch table, the callee is responsible to
       * zero the recv_size if it has finished its job.
       *
       * Not only zero the recv_size, the callee is responsible
       * to zero the buffer, since it contains the length of data.
       * This length of data may be reused if it is not zeroed.
       *
       * Callee is also responsible to set `is_connected` to
       * false if there is a condition where the client should
       * be disconnected.
       *
       * Written by: Ammar Faizi <ammarfaizi2@gmail.com>
       */

      case CLI_PKT_PING:
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        break;

      case CLI_PKT_AUTH:
        tvpn_server_tcp_auth_hander(chan, rdata_size);
        break;

      case CLI_PKT_DATA:
        tvpn_client_tcp_handle_data(chan, rdata_size);
        break;

      case CLI_PKT_DISCONNECT:
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        break;

      default:
        debug_log(3, "Got invalid packet type: %d", cli_pkt->type);
        cli_pkt->size   = 0;
        chan->recv_size = 0;
        break;
    }
  }
}


/**
 * @param tcp_channel *__restrict__ chan
 * @param size_t      rdata_size
 * @return void
 */
inline static void
tvpn_server_tcp_auth_hander(tcp_channel *__restrict__ chan, size_t rdata_size)
{
  client_pkt *cli_pkt = (client_pkt *)chan->recv_buff;

  if (rdata_size < cli_pkt->size) {
    /* Data has not been received completely. */
    return;
  }

  {
    register ssize_t      rv;
    client_auth_tmp       auth_tmp;

    bool                  ret       = false;
    register server_pkt   *srv_pkt  = (server_pkt   *)chan->send_buff;
    register srv_auth_res *auth_res = (srv_auth_res *)srv_pkt->data;
    register auth_pkt     *auth_p   = (auth_pkt     *)cli_pkt->data;

    /* For string safety. */
    auth_p->username[254] = '\0';
    auth_p->password[254] = '\0';

    debug_log(2, "[%s:%d] Received auth data", HP_CC(chan));
    debug_log(2, "[%s:%d] Username: \"%s\"", HP_CC(chan), auth_p->username);
    debug_log(2, "[%s:%d] Password: \"%s\"", HP_CC(chan), auth_p->password);

    if (tvpn_auth_tcp(auth_p, chan, &auth_tmp)) {

      chan->authorized = true;
      srv_pkt->type    = SRV_PKT_AUTH_OK;
      srv_pkt->size    = sizeof(srv_auth_res);

      if (!inet_pton(AF_INET, auth_tmp.ipv4, &(auth_res->ipv4))) {
        debug_log(0,"[%s:%d] Error, invalid ipv4: \"%s\"", 
                  auth_tmp.ipv4);
        goto end;
      }

      if (!inet_pton(AF_INET, auth_tmp.ipv4_netmask,
                              &(auth_res->ipv4_netmask))) {

        debug_log(0, "[%s:%d] Error, invalid ipv4_netmask: \"%s\"",
                  auth_tmp.ipv4_netmask);
        goto end;
      }

    } else {
      srv_pkt->type = SRV_PKT_AUTH_REJECT;
      srv_pkt->size = 0;
    }

    rv = send(chan->cli_fd, srv_pkt,
              SR_IDENT_SIZ + srv_pkt->size, MSG_DONTWAIT);

    if (rv < 0) {
      debug_log(0, "[%s:%d] Error send(): %s", HP_CC(chan), strerror(errno));
      goto end;
    }

    ret = true;

    end:
    if (!ret) {
      close(chan->cli_fd);
      chan->cli_fd       = -1;
      chan->is_connected = false;
    }

    cli_pkt->size   = 0;
    chan->recv_size = 0;
  }
}


/**
 * @param tcp_channel *__restrict__ chan
 * @param size_t      rdata_size
 * @return void
 */
inline static void
tvpn_client_tcp_handle_data(tcp_channel *__restrict__ chan, size_t rdata_size)
{
  client_pkt *cli_pkt = (client_pkt *)chan->recv_buff;

  if (rdata_size < cli_pkt->size) {
    /* Data has not been received completely. */
    return;
  }

  {
    register ssize_t rv;
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
 * @param int signal
 * @return void
 */
inline static void
tvpn_server_tcp_signal_handler(int signal)
{
  (void)signal;
  g_state->stop = true;
}

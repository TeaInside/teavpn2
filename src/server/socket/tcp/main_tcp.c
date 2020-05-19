
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

#include <teavpn2/server/auth.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define TCP_CHANNEL_AMOUNT 10
#define MAX_ERROR_ACCEPT 1024
#define MAX_ERROR_RECV 1024
#define MAX_ERROR_SEND 1024
#define PACKET_ARENA_SIZE 5120
#define CLI_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_cli_pkt) - 1) + ADD_SIZE)
#define SRV_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)
#define SERVER_RECV_BUFFER (PACKET_ARENA_SIZE)
#define FUNC_ZERO_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL == 0) { ACTION; } } while (0)
#define FUNC_ERROR_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL < 0) { perror("Error "#FUNC); ACTION; } } while (0)
#define M_RECV_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(recv(), RETVAL, ACTION)
#define M_RECV_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(recv(), RETVAL, ACTION)
#define M_SEND_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(send(), RETVAL, ACTION)

static void teavpn_server_tcp_stop_all(tcp_master_state *mstate);
static bool teavpn_server_tcp_init(tcp_master_state *mstate);
inline static bool teavpn_server_tcp_socket_setup(int net_fd);
static void *teavpn_server_tcp_iface_reader(void *mstate);
static void *teavpn_server_tcp_accept_worker(void *mstate);
inline static void teavpn_server_tcp_client_accept_init(tcp_master_state *mstate, tcp_channel *chan);
static void *teavpn_server_tcp_client_handle(void *chan);
inline static void teavpn_server_tcp_client_auth(tcp_channel *chan);
inline static int16_t teavpn_server_tcp_extra_recv(tcp_channel *chan);

/**
 * @param iface_info *iinfo
 * @param teavpn_server_config *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *config)
{
  char buf_pipe[8];
  int ret = 0, pipe_read_ret;
  tcp_channel channels[TCP_CHANNEL_AMOUNT];
  tcp_master_state mstate;

  bzero(&mstate, sizeof(mstate));
  bzero(&(mstate.channels), sizeof(mstate.channels));

  mstate.tun_fd = iinfo->tun_fd;
  mstate.config = config;
  mstate.iinfo = iinfo;
  mstate.channels = channels;

  /**
   * Init TCP socket.
   */
  if (!teavpn_server_tcp_init(&mstate)) {
    ret = 1;
    goto close_conn;
  }

  /**
   * Init pipe.
   */
  if (pipe(mstate.pipe_fd) == -1) {
    perror("pipe()");
    goto close_conn;
  }

  pthread_create(&(mstate.iface_reader), NULL, teavpn_server_tcp_iface_reader, (void *)&mstate);
  pthread_create(&(mstate.accept_worker), NULL, teavpn_server_tcp_accept_worker, (void *)&mstate);
  pthread_detach(mstate.iface_reader);
  pthread_detach(mstate.accept_worker);

  /**
   * Master event loop.
   */
  while (true) {
    pipe_read_ret = read(mstate.pipe_fd[0], buf_pipe, sizeof(buf_pipe));
    if (pipe_read_ret < 0) {
      perror("pipe read(): master:");
    }
    if (mstate.stop_all) {
      debug_log(0, "Got stop_all signal");
      debug_log(0, "Stopping everything...");
      goto close_conn;
    }
  }

close_conn:
  if (mstate.net_fd != -1) {
    close(mstate.net_fd);
  }
  if (mstate.pipe_fd[0] != -1) {
    close(mstate.pipe_fd[0]);
  }
  if (mstate.pipe_fd[1] != -1) {
    close(mstate.pipe_fd[1]);
  }
  return ret;
}

/**
 * @param tcp_master_state *mstate
 * @return void
 */
static void teavpn_tcp_stop_all(tcp_master_state *mstate)
{
  ssize_t write_ret;
  mstate->stop_all = true;
  write_ret = write(mstate->pipe_fd[1], "12345678", 8);
  if (write_ret < 0) {
    perror("stop all write()");
  }
}

/**
 * @param tcp_master_state *mstate
 * @return bool
 */
static bool teavpn_server_tcp_init(tcp_master_state *mstate)
{
  /**
   * Create TCP socket.
   */
  debug_log(2, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (mstate->net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(2, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(2, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(mstate->net_fd)) {
    return false;
  }
  debug_log(2, "Socket file descriptor set up successfully");

  /**
   * Prepare server bind address data.
   */
  bzero(&(mstate->server_addr), sizeof(struct sockaddr_in));
  mstate->server_addr.sin_family = AF_INET;
  mstate->server_addr.sin_port = htons(mstate->config->socket.bind_port);
  mstate->server_addr.sin_addr.s_addr = inet_addr(mstate->config->socket.bind_addr);

  /**
   * Bind socket to corresponding address.
   */
  if (bind(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(mstate->server_addr)) < 0) {
    error_log("Bind socket failed");
    perror("Bind failed");
    return false;
  }

  /**
   * Listen.
   */
  if (listen(mstate->net_fd, 3) < 0) {
    error_log("Listen socket failed");
    perror("Listen failed");
    return false;
  }

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Listening on %s:%d...", mstate->config->socket.bind_addr, mstate->config->socket.bind_port);

  return true;
}

/**
 * @param int net_fd
 * @return bool
 */
inline static bool teavpn_server_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }
  return true;
}

/**
 * @param void *mstate
 * @return void *
 */
static void *teavpn_server_tcp_iface_reader(void *mstate)
{
  return NULL;
}

/**
 * @param void *_mstate
 * @return void *
 */
static void *teavpn_server_tcp_accept_worker(void *_mstate)
{
  uint16_t error_count = 0;
  tcp_channel *chosen;
  int16_t fchan_pos = 0;
  tcp_master_state *mstate = (tcp_master_state *)_mstate;
  tcp_channel *channels = mstate->channels;
  socklen_t rlen = sizeof(struct sockaddr_in);

accept:
  /**
   * Accepting client connection.
   */
  chosen = &(channels[fchan_pos]);
  bzero(&(chosen->saddr), sizeof(struct sockaddr_in));
  chosen->fd = accept(mstate->net_fd, (struct sockaddr *)&(chosen->saddr), &rlen);

  if (chosen->fd < 0) {
    error_log("Error on accept!");
    perror("accept()");
    error_count++;

    if (error_count >= MAX_ERROR_ACCEPT) {
      error_log("Reached the max number of error accept.");
      teavpn_tcp_stop_all(mstate);
      goto ret;
    }

    goto accept;
  }

  teavpn_server_tcp_client_accept_init(mstate, chosen);
  pthread_create(&(chosen->thread), NULL, teavpn_server_tcp_client_handle, (void *)chosen);
  pthread_detach(chosen->thread);

  fchan_pos = -1;

prepare_free_channel:
  for (register int16_t i = 0; i < TCP_CHANNEL_AMOUNT; i++) {

    if (!channels[i].is_online) {
      fchan_pos = i;
      break;
    }

  }

  if (fchan_pos == -1) {
    sleep(1);
    debug_log(6, "Client channel is full, re-traversing channels...");
    goto prepare_free_channel;
  }

  /* Back to accepting new client. */
  goto accept;

ret:
  return NULL;
}

/**
 * @param tcp_master_state *mstate
 * @param tcp_channel *chan
 * @return void
 */
inline static void teavpn_server_tcp_client_accept_init(tcp_master_state *mstate, tcp_channel *chan)
{
  /* Set channel state. */
  chan->stop = false;
  chan->is_online = true;
  chan->is_authenticated = false;

  /* Copy client readable address and port. */
  strncpy(chan->saddr_r, inet_ntoa(chan->saddr.sin_addr), 32);
  chan->saddr_r_len = strlen(chan->saddr_r);
  chan->sport_r = ntohs(chan->saddr.sin_port);

  /* Reset error counter. */
  chan->error_recv_count = 0;
  chan->error_send_count = 0;

  /* Plug mstate pointer to client channel. */
  chan->mstate = mstate;
}

#define RECV_ERROR_HANDLE(RETVAL, CHAN, DEFAULT_ACTION, WORST_ACTION) \
  M_RECV_ERROR_HANDLE(RETVAL, { \
    CHAN->error_recv_count++; \
    if (CHAN->error_recv_count >= MAX_ERROR_RECV) { \
      CHAN->stop = true; \
      debug_log(0, "[%s:%d] Reached the max number of error"); \
      WORST_ACTION; \
    } \
    DEFAULT_ACTION; \
  })

#define RECV_ZERO_HANDLE(RETVAL, CHAN, ACTION) \
  M_RECV_ZERO_HANDLE(RETVAL, \
    { \
      CHAN->stop = true; \
      debug_log(4, "[%s:%d] Got zero recv_ret", chan->saddr_r, chan->sport_r); \
      debug_log(0, "[%s:%d] Client disconnect state detected", chan->saddr_r, chan->sport_r); \
      ACTION; \
    } \
  ); \

/**
 * @param void *_chan
 * @return void *
 */
static void *teavpn_server_tcp_client_handle(void *_chan)
{
  char cli_pkt_arena[PACKET_ARENA_SIZE] = {0};
  char srv_pkt_arena[PACKET_ARENA_SIZE] = {0};
  tcp_channel *chan = (tcp_channel *)_chan;
  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)cli_pkt_arena;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;

  chan->cli_pkt = cli_pkt;
  chan->srv_pkt = srv_pkt;

  /* Send auth required signal after connect. */
  srv_pkt->type = SRV_PKT_AUTH_REQUIRED;
  srv_pkt->len  = 0;
  if (send(chan->fd, srv_pkt, SRV_PKT_RSIZE(0), 0) < 0) {
    debug_log(0, "[%s:%d] Failed to send auth signal", chan->saddr_r, chan->sport_r);
    goto close_client;
  }

  /**
   * Client handler event loop.
   */
  while (true) {
    chan->recv_ret = recv(chan->fd, cli_pkt, SERVER_RECV_BUFFER, 0);

    RECV_ERROR_HANDLE(chan->recv_ret, chan,
      /* Default Action. */
      {
        debug_log(0, "[%s:%d] Got error recv_ret", chan->saddr_r, chan->sport_r);
      },

      /* Worst action. */
      {
        debug_log(0, "[%s:%d] Force disconnecting client...", chan->saddr_r, chan->sport_r);
        goto close_client;
      }
    );

    RECV_ZERO_HANDLE(chan->recv_ret, chan, { goto close_client; });

    switch (cli_pkt->type) {
      case CLI_PKT_AUTH:
        break;

      case CLI_PKT_DATA:
        break;

      default:
        debug_log(4, "[%s:%d] Got unknown packet type (%d bytes)",
          chan->saddr_r, chan->sport_r, chan->recv_ret);
        break;
    }

    if (chan->stop) {
      goto close_client;
    }
  }

close_client:
  debug_log(0, "[%s:%d] Closing client connection...", chan->saddr_r, chan->sport_r);
  close(chan->fd);
  chan->is_online = false;
  return NULL;
}

/**
 * @param tcp_channel *chan
 * @return void
 */
inline static void teavpn_server_tcp_client_auth(tcp_channel *chan)
{
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  int16_t recv_ret_tot;

  recv_ret_tot = teavpn_server_tcp_extra_recv(chan);
  if (recv_ret_tot == -1) {
    return;
  }

}

/**
 * @param tcp_channel *chan
 * @return void
 */
inline static int16_t teavpn_server_tcp_extra_recv(tcp_channel *chan)
{
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  char *cli_pktb = (char *)cli_pktb;
  register int16_t recv_ret;
  register int16_t recv_ret_tot = chan->recv_ret;
  register uint16_t data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);

  while (recv_ret_tot < CLI_PKT_RSIZE(0)) {
    recv_ret = recv(chan->fd, &(cli_pktb[recv_ret_tot]), SERVER_RECV_BUFFER, MSG_WAITALL);

    RECV_ERROR_HANDLE(recv_ret, chan, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, chan, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  while (data_ret_tot < cli_pkt->len) {
    recv_ret = recv(chan->fd, &(cli_pktb[recv_ret_tot]), SERVER_RECV_BUFFER, MSG_WAITALL);

    RECV_ERROR_HANDLE(recv_ret, chan, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, chan, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  return recv_ret_tot;
}

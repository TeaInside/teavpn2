
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
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>


#define SERVER_RECV_BUFFER 4096
#define SERVER_RECV_CLIENT_MAX_ERROR 1000
#define SERVER_SEND_CLIENT_MAX_ERROR 1000
#define PACKET_ARENA_SIZE (4096 + 1024)
#define MAX_CLIENT_CHANNEL 10
#define MIN_CLIENT_WAIT_RECV_BYTES (sizeof(teavpn_srv_pkt) - 1)
#define MIN_SERVER_WAIT_RECV_BYTES (sizeof(teavpn_cli_pkt) - 1)
#define MZERO_HANDLE(FUNC, RETVAL, ACT) if (RETVAL == 0) { ACT; }
#define MERROR_HANDLE(FUNC, RETVAL, ACT) if (RETVAL < 0) { perror("Error "#FUNC); ACT; }
#define RECV_ZERO_HANDLE(RETVAL, ACT) MZERO_HANDLE(recv(), RETVAL, ACT)  
#define SEND_ZERO_HANDLE(RETVAL, ACT) MZERO_HANDLE(send(), RETVAL, ACT)
#define READ_ZERO_HANDLE(RETVAL, ACT) MZERO_HANDLE(read(), RETVAL, ACT)
#define WRITE_ZERO_HANDLE(RETVAL, ACT) MZERO_HANDLE(write(), RETVAL, ACT)
#define RECV_ERROR_HANDLE(RETVAL, ACT) MERROR_HANDLE(recv(), RETVAL, ACT)  
#define SEND_ERROR_HANDLE(RETVAL, ACT) MERROR_HANDLE(send(), RETVAL, ACT)
#define READ_ERROR_HANDLE(RETVAL, ACT) MERROR_HANDLE(read(), RETVAL, ACT)
#define WRITE_ERROR_HANDLE(RETVAL, ACT) MERROR_HANDLE(write(), RETVAL, ACT)

typedef struct _teavpn_tcp teavpn_tcp;

typedef struct {
  bool is_online;
  bool is_authenticated;
  pthread_t thread;
  int client_fd;
  char *username;
  uint8_t username_len;
  uint16_t recv_error;
  uint16_t send_error;
  struct {
    char addr[32];
    uint8_t addr_len;
    uint16_t port;
    struct sockaddr_in client_addr;
  } cvt;
  teavpn_tcp *state;
  ssize_t recv_ret;
  ssize_t send_ret;
  teavpn_cli_pkt *cli_pkt;
  teavpn_srv_pkt *srv_pkt;
} tcp_client_channel;

struct _teavpn_tcp {
  int tun_fd;
  int net_fd;
  teavpn_server_config *config;
  struct sockaddr_in server_addr;

  tcp_client_channel channels[MAX_CLIENT_CHANNEL];

  int16_t free_chan_pos; // set -1 if the channels slot is full.

  iface_info *iinfo;
  pthread_t accept_worker_thread;
  pthread_t iface_dispatcher_thread;
};

static bool stop_all = false;
static bool teavpn_server_tcp_init(teavpn_tcp *state);
static void *teavpn_server_tcp_accept_worker(teavpn_tcp *state);
static void *teavpn_server_tcp_iface_dispatcher(teavpn_tcp *state);
static void *teavpn_server_tcp_serve_client(tcp_client_channel *chan);
static bool teavpn_server_tcp_socket_setup(int net_fd);
static void teavpn_server_tcp_handle_auth(tcp_client_channel *chan);
static void teavpn_server_tcp_handle_data(tcp_client_channel *chan);
static void teavpn_server_tcp_handle_extra_recv(tcp_client_channel *chan);

/**
 * @param teavpn_server_config *config
 * @return bool
 */
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *config)
{
  int ret = 0;
  teavpn_tcp state;

  bzero(&state, sizeof(state));
  state.tun_fd = iinfo->tun_fd;

  if (!teavpn_server_tcp_init(&state)) {
    ret = 1;
    goto close;
  }

  pthread_create(&(state.accept_worker_thread), NULL,
    (void * (*)(void *))teavpn_server_tcp_accept_worker, (void *)&state);
  pthread_create(&(state.iface_dispatcher_thread), NULL,
    (void * (*)(void *))teavpn_server_tcp_iface_dispatcher, (void *)&state);

  pthread_detach(state.accept_worker_thread);
  pthread_detach(state.iface_dispatcher_thread);


  while (1) {
    sleep(1);
    if (stop_all) {
      goto close;
    }
  }

close:
  /* Close main TCP socket fd. */
  if (state.net_fd != -1) {
    close(state.net_fd);
  }
  return ret;
}

/**
 * @param teavpn_tcp *state
 * @return bool
 */
static bool teavpn_server_tcp_init(teavpn_tcp *state)
{
  /**
   * Create TCP socket.
   */
  debug_log(3, "Creating TCP socket...");
  state->net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (state->net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(4, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(3, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(state->net_fd)) {
    return false;
  }
  debug_log(4, "Socket file descriptor set up successfully");

  /**
   * Prepare server bind address data.
   */
  memset(&(state->server_addr), 0, sizeof(state->server_addr));
  state->server_addr.sin_family = AF_INET;
  state->server_addr.sin_port = htons(state->config->socket.bind_port);
  state->server_addr.sin_addr.s_addr = inet_addr(state->config->socket.bind_addr);

  /**
   * Bind socket to corresponding address.
   */
  if (bind(state->net_fd, (struct sockaddr *)&(state->server_addr), sizeof(state->server_addr)) < 0) {
    error_log("Bind socket failed");
    perror("Bind failed");
    return false;
  }

  /**
   * Listen.
   */
  if (listen(state->net_fd, 3) < 0) {
    error_log("Listen socket failed");
    perror("Listen failed");
    return false;
  }

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(4, "Listening on %s:%d...",
    state->config->socket.bind_addr, state->config->socket.bind_port);

  /* Init channels with zero bytes. */
  memset(&(state->channels), 0, sizeof(state->channels));

  return true;
}

/**
 * @param teavpn_tcp *state
 * @return void *
 */
static void *teavpn_server_tcp_accept_worker(teavpn_tcp *state)
{
  int client_fd;
  socklen_t rlen = sizeof(struct sockaddr_in);
  register int16_t free_chan_pos = state->free_chan_pos;
  register tcp_client_channel *channels = state->channels;


accept:
  /**
   * Accepting client connection.
   */
  client_fd = accept(state->net_fd,
    (struct sockaddr *)&(channels[free_chan_pos].cvt.client_addr.sin_addr), &rlen);
  if (client_fd < 0) {
    debug_log(1, "An error occured when accepting connection!");
    perror("accept()");
  }

  channels[free_chan_pos].is_online = true;
  channels[free_chan_pos].is_authenticated = false;
  channels[free_chan_pos].client_fd = client_fd;
  channels[free_chan_pos].username = NULL;
  channels[free_chan_pos].username_len = 0;

  strncpy(channels[free_chan_pos].cvt.addr,
    inet_ntoa(channels[free_chan_pos].cvt.client_addr.sin_addr), 31);
  channels[free_chan_pos].cvt.addr[31] = '\0';
  channels[free_chan_pos].cvt.addr_len = strlen(channels[free_chan_pos].cvt.addr);
  if (channels[free_chan_pos].cvt.addr_len > 31) {
    channels[free_chan_pos].cvt.addr_len = 31;
  }
  channels[free_chan_pos].cvt.port = ntohs(channels[free_chan_pos].cvt.client_addr.sin_port);
  channels[free_chan_pos].state = state;

  debug_log(2, "Accepting client (%s:%d)...",
    channels[free_chan_pos].cvt.addr,
    channels[free_chan_pos].cvt.port);

  pthread_create(&(channels[free_chan_pos].thread), NULL,
    (void * (*)(void *))teavpn_server_tcp_serve_client, (void *)&(channels[free_chan_pos]));
  pthread_detach(channels[free_chan_pos].thread);

  /**
   * Preparing for free channel.
   */
prepare_channel:
  free_chan_pos = -1;

  for (register int16_t i = 0; i < MAX_CLIENT_CHANNEL; i++) {
    if (!channels[i].is_online) {
      free_chan_pos = i;
      break;
    }
  }

  if (free_chan_pos == -1) {
    debug_log(6, "Channel is full, retraverse the channel...");
    sleep(1);
    goto prepare_channel;
  }

  explicit_bzero(&(channels[free_chan_pos]), sizeof(tcp_client_channel));
  goto accept;

  return NULL;

  #undef channels
  #undef free_chan_pos
}

/**
 * @param teavpn_tcp *state
 * @return void *
 */
static void *teavpn_server_tcp_iface_dispatcher(teavpn_tcp *state)
{
  return NULL;
}

#define RECV_ERROR_ACTION(L_ACT, W_ACT) \
 { \
    chan->recv_error++; \
    debug_log(6, "[%s:%d](%d) Got error recv_ret", \
      chan->cvt.addr, chan->cvt.port, chan->recv_error); \
    if ((chan->recv_error) >= SERVER_RECV_CLIENT_MAX_ERROR) { \
      debug_log(6, "[%s:%d] Reached the max number of recv error", \
        chan->cvt.addr, chan->cvt.port); \
      W_ACT;\
    } \
    L_ACT; \
  }

/**
 * @param tcp_client_channel *chan
 * @return void *
 */
static void *teavpn_server_tcp_serve_client(tcp_client_channel *chan)
{
  char cli_pkt_arena[PACKET_ARENA_SIZE], srv_pkt_arena[PACKET_ARENA_SIZE];

  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)cli_pkt_arena;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;

  chan->srv_pkt = srv_pkt;
  chan->cli_pkt = cli_pkt;

  /* Send auth required signal after connect. */
  srv_pkt->type = SRV_PKT_AUTH_REQUIRED;
  srv_pkt->len  = 0;
  chan->send_ret = send(chan->client_fd, srv_pkt, MIN_CLIENT_WAIT_RECV_BYTES, 0);
  SEND_ZERO_HANDLE(chan->send_ret, {
    debug_log(6, "[%s:%d] Got zero send_ret", chan->cvt.addr, chan->cvt.port);
    goto close_connection;
  });
  SEND_ERROR_HANDLE(chan->send_ret, {
    debug_log(6, "[%s:%d] Got error send_ret", chan->cvt.addr, chan->cvt.port);
    goto close_connection;
  });

  /* Event loop. */
  while (true) {

    chan->recv_ret = recv(chan->client_fd, cli_pkt, SERVER_RECV_BUFFER, 0);

    /* Handle recv error. */
    RECV_ERROR_HANDLE(chan->recv_ret,
      RECV_ERROR_ACTION({ continue; }, { goto close_connection; }));

    /* Client has been disconnected. */
    RECV_ZERO_HANDLE(chan->recv_ret, {
      debug_log(6, "[%s:%d] Got zero recv_ret", chan->cvt.addr, chan->cvt.port);
      goto close_connection;
    });

    switch (cli_pkt->type) {
      case CLI_PKT_AUTH:
        teavpn_server_tcp_handle_auth(chan);
        break;

      case CLI_PKT_DATA:
        teavpn_server_tcp_handle_data(chan);
        break;

      default:
        debug_log(6, "[%s:%d] Got unknown packet type", chan->cvt.addr, chan->cvt.port);
        break;
    }

    if (!chan->is_online) {
      goto close_connection;
    }
  }

close_connection:
  debug_log(5, "[%s:%d] Closing connection", chan->cvt.addr, chan->cvt.port);
  close(chan->client_fd);
  chan->is_online = false;
  return NULL;
}

/**
 * @param int net_fd
 * @return bool
 */
static bool teavpn_server_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }
  return true;
}

/**
 * @param tcp_client_channel *chan
 * @return void
 */
static void teavpn_server_tcp_handle_auth(tcp_client_channel *chan)
{
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
}

/**
 * @param tcp_client_channel *chan
 * @return void
 */
static void teavpn_server_tcp_handle_data(tcp_client_channel *chan)
{
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
}

/**
 * @param tcp_client_channel *chan
 * @return void
 */
static void teavpn_server_tcp_handle_extra_recv(tcp_client_channel *chan)
{
  ssize_t recv_rtot;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  uint16_t data_received;

  recv_rtot = chan->recv_ret;

  while (recv_rtot < MIN_SERVER_WAIT_RECV_BYTES) {
    /* Handle worst case. */
    /* Even minimal size has not been fullfied. */
    chan->recv_ret = recv(chan->client_fd, &(((char *)cli_pkt)[recv_rtot]), SERVER_RECV_BUFFER, 0);

    /* Handle recv error. */
    RECV_ERROR_HANDLE(chan->recv_ret,
      RECV_ERROR_ACTION({ return; }, {
        chan->is_online = false;
        return;
      }));

    /* Client has been disconnected. */
    RECV_ZERO_HANDLE(chan->recv_ret, {
      debug_log(6, "[%s:%d] Got zero recv_ret", chan->cvt.addr, chan->cvt.port);
      chan->is_online = false;
      return;
    });

    recv_rtot += chan->recv_ret;
  }

  data_received = recv_rtot - MIN_SERVER_WAIT_RECV_BYTES;

  while (data_received < cli_pkt->len) {

    chan->recv_ret = recv(chan->client_fd, &(((char *)cli_pkt)[recv_rtot]), SERVER_RECV_BUFFER, 0);

    /* Handle recv error. */
    RECV_ERROR_HANDLE(chan->recv_ret,
      RECV_ERROR_ACTION({ return; }, {
        chan->is_online = false;
        return;
      }));

    /* Client has been disconnected. */
    RECV_ZERO_HANDLE(chan->recv_ret, {
      debug_log(6, "[%s:%d] Got zero recv_ret", chan->cvt.addr, chan->cvt.port);
      chan->is_online = false;
      return;
    });

    data_received += chan->recv_ret;
    recv_rtot += chan->recv_ret;
  }
}

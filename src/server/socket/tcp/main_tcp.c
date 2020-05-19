
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

#define MAX_ERROR_RECV 1024
#define MAX_ERROR_SEND 1024
#define MAX_ERROR_READ 1024
#define MAX_ERROR_WRITE 1024
#define MAX_ERROR_ACCEPT 1024
#define TCP_CHANNEL_AMOUNT 10
#define PACKET_ARENA_SIZE 5120
#define CLI_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_cli_pkt) - 1) + ADD_SIZE)
#define SRV_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)
#define SERVER_RECV_BUFFER (PACKET_ARENA_SIZE - CLI_PKT_RSIZE(0))
#define SERVER_READ_BUFFER (PACKET_ARENA_SIZE - SRV_PKT_RSIZE(0))
#define FUNC_ZERO_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL == 0) { ACTION; } } while (0)
#define FUNC_ERROR_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL < 0) { perror("Error "#FUNC); ACTION; } } while (0)
#define M_RECV_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(recv(), RETVAL, ACTION)
#define M_SEND_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(send(), RETVAL, ACTION)
#define M_READ_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(read(), RETVAL, ACTION)
#define M_WRITE_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(write(), RETVAL, ACTION)
#define M_RECV_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(recv(), RETVAL, ACTION)
#define M_SEND_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(send(), RETVAL, ACTION)
#define M_READ_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(read(), RETVAL, ACTION)
#define M_WRITE_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(write(), RETVAL, ACTION)
#define RCP chan->saddr_r, chan->sport_r
#define RC "[%s:%d] "

static void teavpn_server_tcp_stop_all(server_tcp_mstate *__restrict__ mstate);
static bool teavpn_server_tcp_init(server_tcp_mstate *mstate);
inline static bool teavpn_server_tcp_socket_setup(int net_fd);
static void *teavpn_server_tcp_iface_reader(void *mstate);
static void *teavpn_server_tcp_accept_worker(void *mstate);
inline static void teavpn_server_tcp_client_accept_init(server_tcp_mstate *__restrict__ mstate, tcp_channel *__restrict__ chan);
static void *teavpn_server_tcp_client_handle(void *chan);
inline static void teavpn_server_tcp_client_auth(tcp_channel *chan);
inline static int16_t teavpn_server_tcp_extra_recv(tcp_channel *chan);
inline static void teavpn_server_tcp_handle_client_data(tcp_channel *chan);

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
  server_tcp_mstate mstate;

  bzero(&mstate, sizeof(mstate));
  bzero(channels, sizeof(channels));

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

  debug_log(0, "Starting network interface reader thread...");
  pthread_create(&(mstate.iface_reader), NULL, teavpn_server_tcp_iface_reader, (void *)&mstate);
  pthread_detach(mstate.iface_reader);

  debug_log(0, "Starting client accept worker thread...");
  pthread_create(&(mstate.accept_worker), NULL, teavpn_server_tcp_accept_worker, (void *)&mstate);
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
 * @param server_tcp_mstate *mstate
 * @return void
 */
static void teavpn_server_tcp_stop_all(server_tcp_mstate *__restrict__ mstate)
{
  ssize_t write_ret;
  mstate->stop_all = true;
  write_ret = write(mstate->pipe_fd[1], (void *)"12345678", 8);
  if (write_ret < 0) {
    perror("stop all write()");
  }
}

/**
 * @param server_tcp_mstate *mstate
 * @return bool
 */
static bool teavpn_server_tcp_init(server_tcp_mstate *mstate)
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
 * @param void *_mstate
 * @return void *
 */
static void *teavpn_server_tcp_iface_reader(void *_mstate)
{
  uint16_t error_count = 0;
  char srv_pkt_arena[PACKET_ARENA_SIZE];
  server_tcp_mstate *mstate = (server_tcp_mstate *)_mstate;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;
  register int tun_fd = mstate->tun_fd;
  register ssize_t read_ret;

  srv_pkt->type = SRV_PKT_DATA;

read_from_tun:
  read_ret = read(tun_fd, srv_pkt->data, SERVER_READ_BUFFER);
  M_READ_ERROR_HANDLE(read_ret, {
    error_count++;
    if (error_count >= MAX_ERROR_READ) {
      debug_log(0, "Reached the max number of error read");
      teavpn_server_tcp_stop_all(mstate);
      goto ret;
    }
    goto read_from_tun;
  });

  M_READ_ZERO_HANDLE(read_ret, {
    debug_log(0, "Read returned zero");
    error_count++;
    if (error_count >= MAX_ERROR_READ) {
      debug_log(0, "Reached the max number of error read");
      teavpn_server_tcp_stop_all(mstate);
      goto ret;
    }
    goto read_from_tun;
  });

  srv_pkt->len = (uint16_t)read_ret;
  debug_log(5, "Read from tun_fd %d bytes", read_ret);

  {
    register ssize_t send_ret;
    register tcp_channel *channels = mstate->channels;

    for (register int16_t i = 0; i < TCP_CHANNEL_AMOUNT; i++) {

      if (channels[i].is_online && channels[i].is_authenticated) {
        send_ret = send(channels[i].fd, srv_pkt, SRV_PKT_RSIZE(srv_pkt->len), MSG_DONTWAIT);

        M_SEND_ERROR_HANDLE(send_ret, {
          channels[i].error_send_count++;
          if (channels[i].error_send_count >= MAX_ERROR_SEND) {
            debug_log(0, RC"Reached the max number of error send", channels[i].saddr_r, channels[i].sport_r);
            channels[i].stop = true;
            continue;
          }
        });

        M_SEND_ZERO_HANDLE(send_ret, {
          channels[i].error_send_count++;
          if (channels[i].error_send_count >= MAX_ERROR_SEND) {
            debug_log(0, RC"Reached the max number of error send", channels[i].saddr_r, channels[i].sport_r);
            channels[i].stop = true;
            continue;
          }
        });
      }

    }
  }


  goto read_from_tun;
ret:
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
  server_tcp_mstate *mstate = (server_tcp_mstate *)_mstate;
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
      teavpn_server_tcp_stop_all(mstate);
      goto ret;
    }

    goto accept;
  }

  teavpn_server_tcp_client_accept_init(mstate, chosen);

  debug_log(0, "Accepting connection from %s:%d...", chosen->saddr_r, chosen->sport_r);

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
 * @param server_tcp_mstate *mstate
 * @param tcp_channel *chan
 * @return void
 */
inline static void teavpn_server_tcp_client_accept_init(server_tcp_mstate *__restrict__ mstate, tcp_channel *__restrict__ chan)
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
      debug_log(0, "[%s:%d](%d) Reached the max number of errors", \
        CHAN->saddr_r, CHAN->sport_r, CHAN->error_recv_count); \
      WORST_ACTION; \
    } \
    DEFAULT_ACTION; \
  })

#define RECV_ZERO_HANDLE(RETVAL, CHAN, ACTION) \
  M_RECV_ZERO_HANDLE(RETVAL, \
    { \
      CHAN->stop = true; \
      debug_log(4, RC"Got zero recv_ret", CHAN->saddr_r, CHAN->sport_r); \
      debug_log(0, RC"Client disconnect state detected", CHAN->saddr_r, CHAN->sport_r); \
      ACTION; \
    } \
  ); \

/**
 * @param void *_chan
 * @return void *
 */
static void *teavpn_server_tcp_client_handle(void *_chan)
{
  register ssize_t send_ret = 0;
  char cli_pkt_arena[PACKET_ARENA_SIZE] = {0};
  char srv_pkt_arena[PACKET_ARENA_SIZE] = {0};
  tcp_channel *chan = (tcp_channel *)_chan;
  server_tcp_mstate *mstate = chan->mstate;
  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)cli_pkt_arena;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;

  chan->cli_pkt = cli_pkt;
  chan->srv_pkt = srv_pkt;

  /* Send auth required signal after connect. */
  srv_pkt->type = SRV_PKT_AUTH_REQUIRED;
  srv_pkt->len  = 0;
  debug_log(3, RC"Sending SRV_PKT_AUTH_REQUIRED...", RCP);

  send_ret = send(chan->fd, srv_pkt, SRV_PKT_RSIZE(0), 0);
  if (send_ret < 0) {
    perror("send");
    debug_log(0, RC"Failed to send auth signal", RCP);
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
        debug_log(0, RC"Got error recv_ret", RCP);
        continue;
      },

      /* Worst action. */
      {
        debug_log(0, RC"Force disconnecting client...", RCP);
        goto close_client;
      }
    );

    RECV_ZERO_HANDLE(chan->recv_ret, chan, { goto close_client; });

    switch (cli_pkt->type) {
      case CLI_PKT_AUTH:
        debug_log(2, RC"Got CLI_PKT_AUTH", RCP);
        teavpn_server_tcp_client_auth(chan);
        break;

      case CLI_PKT_DATA:
        debug_log(7, RC"Got CLI_PKT_DATA", RCP);
        teavpn_server_tcp_handle_client_data(chan);
        break;

      default:
        debug_log(4, RC"Got unknown packet type (%d bytes)", RCP, chan->recv_ret);
        break;
    }

    if (chan->stop || mstate->stop_all) {
      goto close_client;
    }
  }

close_client:
  debug_log(0, RC"Closing client connection...", RCP);
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
  ssize_t send_ret;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  teavpn_srv_pkt *srv_pkt = chan->srv_pkt;
  teavpn_cli_auth *auth = (teavpn_cli_auth *)cli_pkt->data;
  teavpn_srv_iface_info *iface_info = (teavpn_srv_iface_info *)srv_pkt->data;
  int16_t recv_ret_tot;

  recv_ret_tot = teavpn_server_tcp_extra_recv(chan);
  if (recv_ret_tot == -1) {
    return;
  }

  debug_log(8, RC"Username: \"%s\"", RCP, auth->username);
  debug_log(8, RC"Password: \"%s\"", RCP, auth->password);

  if (teavpn_server_auth_handle(auth->username, auth->password, chan->mstate->config, iface_info)) {
    debug_log(8, RC"Authentication success!", RCP);
    chan->is_authenticated = true;
    srv_pkt->type = SRV_PKT_IFACE_INFO;
    srv_pkt->len  = sizeof(teavpn_srv_iface_info);
    send_ret = send(chan->fd, srv_pkt, SRV_PKT_RSIZE(sizeof(teavpn_srv_iface_info)), 0);
    M_SEND_ERROR_HANDLE(send_ret, {
      debug_log(0, RC"An error occured when sending SRV_PKT_AUTH_ACCEPTED", RCP);
    });

  } else {

  }
}

/**
 * @param tcp_channel *chan
 * @return void
 */
inline static int16_t teavpn_server_tcp_extra_recv(tcp_channel *chan)
{
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  char *cli_pktb = (char *)cli_pkt;
  register int16_t recv_ret;
  register int16_t recv_ret_tot = chan->recv_ret;
  register uint16_t data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);

  while (recv_ret_tot < CLI_PKT_RSIZE(0)) {
    debug_log(5, RC"Re-receiving...", RCP);

    recv_ret = recv(chan->fd, &(cli_pktb[recv_ret_tot]), SERVER_RECV_BUFFER, 0);

    RECV_ERROR_HANDLE(recv_ret, chan, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, chan, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  while (data_ret_tot < cli_pkt->len) {
    debug_log(5, RC"Re-receiving...", RCP);

    recv_ret = recv(chan->fd, &(cli_pktb[recv_ret_tot]), SERVER_RECV_BUFFER, 0);

    RECV_ERROR_HANDLE(recv_ret, chan, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, chan, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  return recv_ret_tot;
}

/**
 * @param tcp_channel *chan
 * @return void
 */
inline static void teavpn_server_tcp_handle_client_data(tcp_channel *chan)
{
  register ssize_t write_ret;
  server_tcp_mstate *mstate = chan->mstate;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  int16_t recv_ret_tot;

  recv_ret_tot = teavpn_server_tcp_extra_recv(chan);
  if (recv_ret_tot == -1) {
    return;
  }

  write_ret = write(mstate->tun_fd, cli_pkt->data, cli_pkt->len);
  M_WRITE_ERROR_HANDLE(write_ret, {
    mstate->error_write_count++;
    if (mstate->error_write_count >= MAX_ERROR_WRITE) {
      debug_log(0, "Reached the max number of error write");
      teavpn_server_tcp_stop_all(mstate);
      return;
    }
  });

  M_WRITE_ZERO_HANDLE(write_ret, {
    debug_log(0, RC"write_ret returned zero", RCP);
    mstate->error_write_count++;
    if (mstate->error_write_count >= MAX_ERROR_WRITE) {
      debug_log(0, "Reached the max number of error write");
      teavpn_server_tcp_stop_all(mstate);
      return;
    }
  });

  debug_log(5, "Write to tun_fd %d bytes", write_ret);
}

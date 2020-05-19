
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
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>

#define MAX_ERROR_RECV 1024
#define MAX_ERROR_SEND 1024
#define MAX_ERROR_READ 1024
#define MAX_ERROR_WRITE 1024
#define PACKET_ARENA_SIZE 5120
#define CLIENT_RECV_BUFFER (PACKET_ARENA_SIZE)
#define CLIENT_READ_BUFFER (PACKET_ARENA_SIZE)
#define CLI_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_cli_pkt) - 1) + ADD_SIZE)
#define SRV_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)
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

static void teavpn_client_tcp_stop_all(client_tcp_mstate *__restrict__ mstate);
inline static bool teavpn_client_tcp_init(client_tcp_mstate *__restrict__ mstate);
inline static bool teavpn_client_tcp_socket_setup(int net_fd);
static void *teavpn_client_recv_worker(void *mstate);
inline static bool teavpn_client_tcp_send_auth(client_tcp_mstate *__restrict__ mstate);
inline static bool teavpn_client_tcp_iface_init(client_tcp_mstate *__restrict__ mstate);
static void *teavpn_client_tcp_iface_reader(void *mstate);
inline static void teavpn_client_tcp_write_iface(client_tcp_mstate *__restrict__ mstate);
inline static int16_t teavpn_client_tcp_extra_recv(client_tcp_mstate *__restrict__ mstate);

/**
 * @param teavpn_client_config *config
 * @return bool
 */
__attribute__((force_align_arg_pointer))
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *config)
{
  char buf_pipe[8];
  int ret = 0, pipe_read_ret;
  client_tcp_mstate mstate;

  bzero(&mstate, sizeof(mstate));

  mstate.tun_fd = iinfo->tun_fd;
  mstate.config = config;
  mstate.iinfo = iinfo;

  /**
   * Init TCP socket.
   */
  if (!teavpn_client_tcp_init(&mstate)) {
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

  pthread_create(&(mstate.recv_worker), NULL, teavpn_client_recv_worker, (void *)&mstate);
  pthread_detach(mstate.recv_worker);

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
    debug_log(0, "Closing connection...");
    close(mstate.net_fd);
  }
  return ret;
}

/**
 * @param client_tcp_mstate *mstate
 * @return void
 */
static void teavpn_client_tcp_stop_all(client_tcp_mstate *__restrict__ mstate)
{
  ssize_t write_ret;
  mstate->stop_all = true;
  write_ret = write(mstate->pipe_fd[1], (void *)"12345678", 8);
  if (write_ret < 0) {
    perror("stop all write()");
  }
}

/**
 * @param client_tcp_mstate *mstate
 * @return bool
 */
inline static bool teavpn_client_tcp_init(client_tcp_mstate *__restrict__ mstate)
{
  /**
   * Create TCP socket.
   */
  debug_log(0, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (mstate->net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(0, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(0, "Setting up socket file descriptor...");
  if (!teavpn_client_tcp_socket_setup(mstate->net_fd)) {
    perror("Error setsockopt()");
    return false;
  }
  debug_log(0, "Socket file descriptor set up successfully");

  /**
   * Prepare server address and port.
   */
  bzero(&(mstate->server_addr), sizeof(mstate->server_addr));
  mstate->server_addr.sin_family = AF_INET;
  mstate->server_addr.sin_port = htons(mstate->config->socket.server_port);
  mstate->server_addr.sin_addr.s_addr = inet_addr(mstate->config->socket.server_addr);

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Connecting to %s:%d...", mstate->config->socket.server_addr, mstate->config->socket.server_port);

  if (connect(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(struct sockaddr_in)) < 0) {
    perror("Error on connect");
    return false;
  }

  debug_log(0, "Connection established!");

  return true;
}

/**
 * @param int net_fd
 * @return bool
 */
inline static bool teavpn_client_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }

  return true;
}

#define RECV_ERROR_HANDLE(RETVAL, MSTATE, DEFAULT_ACTION, WORST_ACTION) \
  M_RECV_ERROR_HANDLE(RETVAL, { \
    MSTATE->error_recv_count++; \
    if (MSTATE->error_recv_count >= MAX_ERROR_RECV) { \
      MSTATE->stop_all = true; \
      debug_log(0, "[%d] Reached the max number of errors", MSTATE->error_recv_count); \
      teavpn_client_tcp_stop_all(MSTATE); \
      WORST_ACTION; \
    } \
    DEFAULT_ACTION; \
  })

#define RECV_ZERO_HANDLE(RETVAL, MSTATE, ACTION) \
  M_RECV_ZERO_HANDLE(RETVAL, \
    { \
      MSTATE->stop_all = true; \
      debug_log(4, "Got zero recv_ret"); \
      debug_log(0, "Server disconnect state detected"); \
      teavpn_client_tcp_stop_all(MSTATE); \
      ACTION; \
    } \
  ); \

/**
 * @param void *_mstate
 * @return void *
 */
static void *teavpn_client_recv_worker(void *_mstate)
{
  char srv_pkt_arena[PACKET_ARENA_SIZE];
  char cli_pkt_arena[PACKET_ARENA_SIZE];
  client_tcp_mstate *mstate = (client_tcp_mstate *)_mstate;
  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)srv_pkt_arena;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)cli_pkt_arena;

  mstate->cli_pkt = cli_pkt;
  mstate->srv_pkt = srv_pkt;

  /**
   * Event loop.
   */
  while (true) {
    mstate->recv_ret = recv(mstate->net_fd, srv_pkt, CLIENT_RECV_BUFFER, 0);

    RECV_ERROR_HANDLE(mstate->recv_ret, mstate,
      /* Default Action. */
      {
        debug_log(0, "Got error recv_ret");
        continue;
      },

      /* Worst action. */
      {
        debug_log(0, "Force disconnecting server...");
        goto ret;
      }
    );

    RECV_ZERO_HANDLE(mstate->recv_ret, mstate, { goto ret; });

    switch (srv_pkt->type) {

      case SRV_PKT_AUTH_REQUIRED:
        debug_log(0, "Got SRV_PKT_AUTH_REQUIRED");
        if (!teavpn_client_tcp_send_auth(mstate)) {
          debug_log(0, "Failed to send auth data");
          teavpn_client_tcp_stop_all(mstate);
          goto ret;
        }
        break;

      case SRV_PKT_AUTH_REJECTED:
        debug_log(0, "Authentication failed!");
        debug_log(0, "Got SRV_PKT_AUTH_REJECTED");
        teavpn_client_tcp_stop_all(mstate);
        goto ret;
        break;

      case SRV_PKT_IFACE_INFO:
        debug_log(0, "Authentication success!");
        debug_log(0, "Got SRV_PKT_IFACE_INFO");
        if (teavpn_client_tcp_iface_init(mstate)) {
          debug_log(0, "Starting network interface reader thread...");
          pthread_create(&(mstate->iface_reader), NULL, teavpn_client_tcp_iface_reader, (void *)mstate);
          pthread_detach(mstate->iface_reader);
        } else {
          debug_log(0, "Cannot initialize interface");
          teavpn_client_tcp_stop_all(mstate);
          goto ret;
        }
        break;

      case SRV_PKT_DATA:
        debug_log(7, "Got SRV_PKT_DATA");
        teavpn_client_tcp_write_iface(mstate);
        break;

      default:
        debug_log(4, "Got unknown packet type (%d bytes)", mstate->recv_ret);
        break;
    }

    if (mstate->stop_all) {
      goto ret;
    }
  }

ret:
  return NULL;
}

/**
 * @param client_tcp_mstate *mstate
 * @return bool
 */
inline static bool teavpn_client_tcp_send_auth(client_tcp_mstate *__restrict__ mstate)
{
  teavpn_cli_pkt *cli_pkt = mstate->cli_pkt;
  teavpn_cli_auth *auth = (teavpn_cli_auth *)cli_pkt->data;

  bzero(auth, sizeof(teavpn_cli_auth));
  cli_pkt->type = CLI_PKT_AUTH;
  cli_pkt->len  = sizeof(teavpn_cli_auth);
  strcpy(auth->username, mstate->config->auth.username);
  strcpy(auth->password, mstate->config->auth.password);

  debug_log(0, "Authenticating...");
  mstate->send_ret = send(mstate->net_fd, cli_pkt, CLI_PKT_RSIZE(sizeof(teavpn_cli_auth)), MSG_CONFIRM);
  M_SEND_ERROR_HANDLE(mstate->send_ret, { return false; });
  M_SEND_ZERO_HANDLE(mstate->send_ret, { return false; });

  return true;
}

/**
 * @param client_tcp_mstate *mstate
 * @return bool
 */
inline static bool teavpn_client_tcp_iface_init(client_tcp_mstate *__restrict__ mstate)
{
  teavpn_srv_iface_info *iface = (teavpn_srv_iface_info *)(mstate->srv_pkt->data);

  debug_log(0, "inet4: \"%s\"", iface->inet4);
  debug_log(0, "inet4_bc: \"%s\"", iface->inet4_bc);

  strcpy(mstate->config->iface.inet4, iface->inet4);
  strcpy(mstate->config->iface.inet4_bcmask, iface->inet4_bc);

  debug_log(0, "Setting up teavpn network interface...");
  if (!teavpn_iface_init(&(mstate->config->iface))) {
    error_log("Cannot set up teavpn network interface");
    return false;
  }

  return true;
}

/**
 * @param void *_mstate
 * @return void *
 */
static void *teavpn_client_tcp_iface_reader(void *_mstate)
{
  register ssize_t read_ret;
  uint16_t error_count = 0;
  client_tcp_mstate *mstate = (client_tcp_mstate *)_mstate;
  register teavpn_cli_pkt *cli_pkt = mstate->cli_pkt;

  cli_pkt->type = CLI_PKT_DATA;

  while (true) {

    /**
     * Read from tun_fd.
     */
    read_ret = read(mstate->tun_fd, cli_pkt->data, CLIENT_READ_BUFFER);
    M_READ_ERROR_HANDLE(read_ret, {
      error_count++;
      if (error_count >= MAX_ERROR_READ) {
        debug_log(0, "Reached the max number of error read()");
        teavpn_client_tcp_stop_all(mstate);
        goto ret;
      }
      goto eloop_cycle;
    });

    M_READ_ZERO_HANDLE(read_ret, {
      debug_log(0, "Read returned zero");
      error_count++;
      if (error_count >= MAX_ERROR_READ) {
        debug_log(0, "Reached the max number of error read()");
        teavpn_client_tcp_stop_all(mstate);
        goto ret;
      }
      goto eloop_cycle;
    });

    debug_log(5, "Read from tun_fd %d bytes", read_ret);

    /**
     * Send data to server.
     */
    cli_pkt->len = (uint16_t)read_ret;

    mstate->send_ret = send(mstate->net_fd, cli_pkt, CLI_PKT_RSIZE(cli_pkt->len), MSG_DONTWAIT);
    M_SEND_ERROR_HANDLE(mstate->send_ret, {
      mstate->error_send_count++;
      if (mstate->error_send_count >= MAX_ERROR_SEND) {
        debug_log(0, "Reached the max number of error read()");
        teavpn_client_tcp_stop_all(mstate);
        goto ret;
      }
      goto eloop_cycle;
    });

    M_SEND_ZERO_HANDLE(mstate->send_ret, {
      debug_log(0, "Send returned zero");
      mstate->error_send_count++;
      if (mstate->error_send_count >= MAX_ERROR_SEND) {
        debug_log(0, "Reached the max number of error read()");
        teavpn_client_tcp_stop_all(mstate);
        goto ret;
      }
      goto eloop_cycle;
    });

eloop_cycle:
    if (mstate->stop_all) {
      goto ret;
    }
  }

ret:
  return NULL;
}

/**
 * @param client_tcp_mstate *mstate
 * @return int16_t
 */
inline static int16_t teavpn_client_tcp_extra_recv(client_tcp_mstate *__restrict__ mstate)
{
  teavpn_srv_pkt *srv_pkt = mstate->srv_pkt;
  char *srv_pktb = (char *)srv_pkt;
  register int16_t recv_ret;
  register int16_t recv_ret_tot = mstate->recv_ret;
  register uint16_t data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);

  while (recv_ret_tot < CLI_PKT_RSIZE(0)) {
    debug_log(5, "Re-receiving...");

    recv_ret = recv(mstate->net_fd, &(srv_pktb[recv_ret_tot]), CLIENT_RECV_BUFFER, MSG_WAITALL);

    RECV_ERROR_HANDLE(recv_ret, mstate, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, mstate, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  while (data_ret_tot < srv_pkt->len) {
    debug_log(5, "Re-receiving...");

    recv_ret = recv(mstate->net_fd, &(srv_pktb[recv_ret_tot]), CLIENT_RECV_BUFFER, MSG_WAITALL);

    RECV_ERROR_HANDLE(recv_ret, mstate, { return -1; }, { return -1; });
    RECV_ZERO_HANDLE(recv_ret, mstate, { return -1; });

    recv_ret_tot += recv_ret;
    data_ret_tot = ((uint16_t)recv_ret_tot) - CLI_PKT_RSIZE(0);
  }

  return recv_ret_tot;
}

/**
 * @param client_tcp_mstate *mstate
 * @return void
 */
inline static void teavpn_client_tcp_write_iface(client_tcp_mstate *__restrict__ mstate)
{
  register ssize_t write_ret;
  register teavpn_srv_pkt *srv_pkt = mstate->srv_pkt;
  register int16_t recv_ret_tot;

  recv_ret_tot = teavpn_client_tcp_extra_recv(mstate);
  if (recv_ret_tot == -1) {
    return;
  }

  write_ret = write(mstate->tun_fd, srv_pkt->data, srv_pkt->len);
  M_WRITE_ERROR_HANDLE(write_ret, {
    mstate->error_write_count++;
    if (mstate->error_write_count >= MAX_ERROR_WRITE) {
      debug_log(0, "Reached the max number of error");
      teavpn_client_tcp_stop_all(mstate);
      return;
    }
  });

  M_WRITE_ZERO_HANDLE(write_ret, {
    debug_log(0, "Write returned zero");
    mstate->error_write_count++;
    if (mstate->error_write_count >= MAX_ERROR_WRITE) {
      debug_log(0, "Reached the max number of error");
      teavpn_client_tcp_stop_all(mstate);
      return;
    }
  });

  debug_log(5, "Write to tun_fd %d bytes", write_ret);
}

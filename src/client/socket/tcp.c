
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
#include <teavpn2/global/data_struct.h>
#include <teavpn2/client/common.h>
#include <teavpn2/server/socket/tcp.h>


#define CLIENT_RECV_BUFFER 4096
#define CLIENT_READ_BUFFER 4096
#define CLIENT_RECV_SERVER_MAX_ERROR 1024
#define CLIENT_SEND_SERVER_MAX_ERROR 1024
#define CLIENT_TUN_READ_MAX_ERROR 1024
#define CLIENT_TUN_WRITE_MAX_ERROR 1024
#define SERVER_RECV_BUFFER 4096
#define SERVER_READ_BUFFER 4096
#define SERVER_RECV_CLIENT_MAX_ERROR 1024
#define SERVER_SEND_CLIENT_MAX_ERROR 1024
#define SERVER_TUN_READ_MAX_ERROR 1024
#define SERVER_TUN_WRITE_MAX_ERROR 1024
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

struct _teavpn_tcp {
  int tun_fd;
  int net_fd;
  teavpn_client_config *config;
  iface_info *iinfo;
  ssize_t recv_ret;
  ssize_t send_ret;
  ssize_t write_ret;
  ssize_t read_ret;
  uint16_t recv_error;
  uint16_t send_error;
  uint16_t write_error;
  uint16_t read_error;
  struct sockaddr_in server_addr;
  teavpn_srv_pkt *srv_pkt;
  teavpn_cli_pkt *cli_pkt;
  pthread_t recv_worker_thread;
  pthread_t iface_dispatcher_thread;
};

static bool stop_all = false;
static bool teavpn_client_tcp_init(teavpn_tcp *state);
static bool teavpn_client_tcp_socket_setup(int net_fd);
static void *teavpn_client_tcp_recv_worker(teavpn_tcp *state);
static void *teavpn_client_tcp_iface_dispatcher(teavpn_tcp *state);
static bool teavpn_client_tcp_send_auth(teavpn_tcp *state);
static bool teavpn_client_tcp_init_iface(teavpn_tcp *state);
static void teavpn_client_tcp_write_iface(teavpn_tcp *state);
static void teavpn_client_tcp_handle_extra_recv(teavpn_tcp *state);


/**
 * @param teavpn_client_config *config
 * @return bool
 */
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *config)
{
  int ret;
  teavpn_tcp state;

  bzero(&state, sizeof(state));

  state.config = config;
  state.tun_fd = iinfo->tun_fd;
  state.iinfo = iinfo;

  if (!teavpn_client_tcp_init(&state)) {
    ret = 1;
    goto close_net;
  }

  pthread_create(&(state.recv_worker_thread), NULL,
    (void * (*)(void *))teavpn_client_tcp_recv_worker, (void *)&state);
  pthread_create(&(state.iface_dispatcher_thread), NULL,
    (void * (*)(void *))teavpn_client_tcp_iface_dispatcher, (void *)&state);

  pthread_detach(state.recv_worker_thread);
  pthread_detach(state.iface_dispatcher_thread);

  while (true) {
    sleep(1);
    if (stop_all) {
      goto close_net;
    }
  }

close_net:
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
static bool teavpn_client_tcp_init(teavpn_tcp *state)
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
  debug_log(1, "Setting up socket file descriptor...");
  if (!teavpn_client_tcp_socket_setup(state->net_fd)) {
    perror("Error setsockopt()");
    return false;
  }
  debug_log(4, "Socket file descriptor set up successfully");

  /**
   * Prepare server address and port.
   */
  bzero(&(state->server_addr), sizeof(state->server_addr));
  state->server_addr.sin_family = AF_INET;
  state->server_addr.sin_port = htons(state->config->socket.server_port);
  state->server_addr.sin_addr.s_addr = inet_addr(state->config->socket.server_addr);

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Connecting to %s:%d...",
    state->config->socket.server_addr, state->config->socket.server_port);
  if (connect(state->net_fd, (struct sockaddr *)&(state->server_addr),
    sizeof(struct sockaddr_in)) < 0) {
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
static bool teavpn_client_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }

  return true;
}

/**
 * @param teavpn_tcp *state
 * @return void *
 */
static void *teavpn_client_tcp_recv_worker(teavpn_tcp *state)
{
  char srv_pkt_arena[PACKET_ARENA_SIZE], cli_pkt_arena[PACKET_ARENA_SIZE];
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;
  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)cli_pkt_arena;

  state->srv_pkt = srv_pkt;
  state->cli_pkt = cli_pkt;

  while (true) {
    state->recv_ret = recv(state->net_fd, srv_pkt, CLIENT_RECV_BUFFER, 0);
    RECV_ERROR_HANDLE(state->recv_ret, {
      state->recv_error++;
      if (state->recv_error >= CLIENT_RECV_SERVER_MAX_ERROR) {
        debug_log(0, "Reached the max number of recv error");
        debug_log(0, "Stopping everything...");
        stop_all = true;
        return NULL;
      }
    });
    RECV_ZERO_HANDLE(state->recv_ret, {
      debug_log(0, "Disconnected from server.");
      debug_log(0, "Stopping everything...");
      stop_all = true;
      return NULL;
    });

    switch (srv_pkt->type) {
      case SRV_PKT_AUTH_REQUIRED:
        debug_log(0, "Got SRV_PKT_AUTH_REQUIRED");
        if (!teavpn_client_tcp_send_auth(state)) {
          stop_all = true;
          debug_log(0, "Failed to send auth data");
          return NULL;
        }
        break;
      case SRV_PKT_AUTH_REJECTED:
        stop_all = true;
        debug_log(0, "Authentication failed!");
        return NULL;
        break;
      case SRV_PKT_AUTH_ACCEPTED:
        debug_log(0, "Authenticated!");
        break;
      case SRV_PKT_IFACE_INFO:
        if (!teavpn_client_tcp_init_iface(state)) {
          stop_all = true;
          debug_log(0, "Stopping everything...");
          return NULL;
        }
        break;
      case SRV_PKT_DATA:
        teavpn_client_tcp_write_iface(state);
        break;
    }
  }
}

/**
 * @param teavpn_tcp *state
 * @return void *
 */
static void *teavpn_client_tcp_iface_dispatcher(teavpn_tcp *state)
{
  teavpn_srv_pkt *srv_pkt = state->srv_pkt;
  srv_pkt->type = CLI_PKT_DATA;

read_from_tun:
  state->read_ret = read(state->tun_fd, srv_pkt->data, CLIENT_READ_BUFFER);
  READ_ERROR_HANDLE(state->read_ret, {
    state->read_error++;
    debug_log(0, "Read from tun_fd got error");
    if (state->read_error > CLIENT_TUN_READ_MAX_ERROR) {
      debug_log(0, "Read from tun_fd has reached the max number error");
      debug_log(0, "Stopping everything...");
      stop_all = true;
      return NULL;
    }
    goto read_from_tun;
  });
  READ_ZERO_HANDLE(state->read_ret, {
    debug_log(0, "Read from tun_fd returned zero");
    debug_log(0, "Stopping everything...");
    stop_all = true;
    return NULL;
  });
  debug_log(5, "Read from tun_fd %d bytes", state->read_ret);

  srv_pkt->len = (uint16_t)state->read_ret;
  state->send_ret = send(state->net_fd, srv_pkt, MIN_SERVER_WAIT_RECV_BYTES + srv_pkt->len, 0);
  SEND_ERROR_HANDLE(state->send_ret, {
    state->send_error++;
    if (state->send_error > SERVER_SEND_CLIENT_MAX_ERROR) {
      debug_log(0, "Reached the max number of send error");
      debug_log(0, "Stopping everything...");
      stop_all = true;
      return NULL;
    }
  });
  SEND_ZERO_HANDLE(state->send_ret, {
    debug_log(0, "Send to net_fd returned zero");
    debug_log(0, "Stopping everything...");
    stop_all = true;
    return NULL;
  });

goto read_from_tun;
  return NULL;
}

/**
 * @param teavpn_tcp *state
 * @return bool
 */
static bool teavpn_client_tcp_send_auth(teavpn_tcp *state)
{
  teavpn_cli_pkt *cli_pkt = state->cli_pkt;
  teavpn_cli_auth *auth = (teavpn_cli_auth *)cli_pkt->data;

  strcpy(auth->username, state->config->auth.username);
  strcpy(auth->password, state->config->auth.password);
  cli_pkt->type = CLI_PKT_AUTH;
  cli_pkt->len = sizeof(teavpn_cli_auth);

  state->send_ret = send(state->net_fd, cli_pkt, MIN_SERVER_WAIT_RECV_BYTES + sizeof(teavpn_cli_auth), 0);
  SEND_ERROR_HANDLE(state->send_ret, {
    return false;
  });

  return true;
}

/**
 * @param teavpn_srv_pkt *srv_pkt
 * @return void
 */
static bool teavpn_client_tcp_init_iface(teavpn_tcp *state)
{
  teavpn_srv_iface_info *iface = (teavpn_srv_iface_info *)(state->srv_pkt->data);

  debug_log(2, "inet4: \"%s\"", iface->inet4);
  debug_log(2, "inet4_bc: \"%s\"", iface->inet4_bc);

  strcpy(state->config->iface.inet4, iface->inet4);
  strcpy(state->config->iface.inet4_bcmask, iface->inet4_bc);

  debug_log(2, "Setting up teavpn network interface...");
  if (!teavpn_iface_init(&(state->config->iface))) {
    error_log("Cannot set up teavpn network interface");
    return false;
  }

  return true;
}

/**
 * @param teavpn_tcp *state
 * @return void
 */
static void teavpn_client_tcp_write_iface(teavpn_tcp *state)
{
  teavpn_srv_pkt *srv_pkt = state->srv_pkt;
  teavpn_client_tcp_handle_extra_recv(state);

  state->write_ret = write(state->tun_fd, srv_pkt->data, srv_pkt->len);
  WRITE_ERROR_HANDLE(state->write_ret, {
    state->write_error++;
    if (state->write_error >= CLIENT_TUN_WRITE_MAX_ERROR) {
      debug_log(0, "Reached the max number of write error");
      debug_log(0, "Stopping everything");
      stop_all = true;
      return;
    }
  });

  debug_log(5, "Write to tun_fd %d bytes", state->write_ret);
}

#define RECV_ERROR_ACTION(L_ACT, W_ACT) \
 { \
    state->recv_error++; \
    debug_log(6, "(%d) Got error recv_ret", state->recv_error); \
    if ((state->recv_error) >= SERVER_RECV_CLIENT_MAX_ERROR) { \
      debug_log(6, "Reached the max number of recv error"); \
      W_ACT;\
    } \
    L_ACT; \
  }

/**
 * @param teavpn_tcp *state
 * @return void
 */
static void teavpn_client_tcp_handle_extra_recv(teavpn_tcp *state)
{
  ssize_t recv_rtot;
  teavpn_srv_pkt *srv_pkt = state->srv_pkt;
  uint16_t data_received;

  recv_rtot = state->recv_ret;

  while (recv_rtot < MIN_CLIENT_WAIT_RECV_BYTES) {
    /* Handle worst case. */
    /* Even minimal size has not been fullfied. */
    state->recv_ret = recv(state->net_fd, &(((char *)srv_pkt)[recv_rtot]), CLIENT_RECV_BUFFER, 0);

    /* Handle recv error. */
    RECV_ERROR_HANDLE(state->recv_ret,
      RECV_ERROR_ACTION({ return; }, {
        stop_all = true;
        return;
      }));

    /* Client has been disconnected. */
    RECV_ZERO_HANDLE(state->recv_ret, {
      debug_log(6, "Got zero recv_ret");
      stop_all = true;
      return;
    });

    recv_rtot += state->recv_ret;
  }

  data_received = recv_rtot - MIN_CLIENT_WAIT_RECV_BYTES;

  while (data_received < srv_pkt->len) {

    state->recv_ret = recv(state->net_fd, &(((char *)srv_pkt)[recv_rtot]), CLIENT_RECV_BUFFER, 0);

    /* Handle recv error. */
    RECV_ERROR_HANDLE(state->recv_ret,
      RECV_ERROR_ACTION({ return; }, {
        stop_all = true;
        return;
      }));

    /* Server has been disconnected. */
    RECV_ZERO_HANDLE(state->recv_ret, {
      debug_log(6, "Got zero recv_ret");
      stop_all = true;
      return;
    });

    data_received += state->recv_ret;
    recv_rtot += state->recv_ret;
  }
}

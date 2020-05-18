
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
  struct sockaddr_in server_addr;
  pthread_t recv_worker_thread;
  pthread_t iface_dispatcher_thread;
};

static bool stop_all = false;
static bool teavpn_client_tcp_init(teavpn_tcp *state);
static bool teavpn_client_tcp_socket_setup(int net_fd);
static void *teavpn_client_tcp_recv_worker(teavpn_tcp *state);
static void *teavpn_client_tcp_iface_dispatcher(teavpn_tcp *state);

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

}

/**
 * @param teavpn_tcp *state
 * @return void *
 */
static void *teavpn_client_tcp_iface_dispatcher(teavpn_tcp *state)
{

}
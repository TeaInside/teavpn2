
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
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>
#include <teavpn2/global/data_struct.h>

#define RECV_BUFFER 4096
#define TUN_READ_SIZE 4096
#define MAX_CLIENT_CHANNEL 10
#define TUN_MAX_READ_ERROR 1000
#define CLIENT_MAX_WRITE_ERROR 1000
#define MIN_WAIT_RECV_BYTES (SRV_PKT_HSIZE)
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

static int tun_fd;
static int net_fd;
static teavpn_client_config *config;

static bool teavpn_client_tcp_init();
static bool teavpn_client_tcp_socket_setup();
static int teavpn_client_tcp_server_wait(teavpn_srv_pkt *srv_pkt);
static bool teavpn_client_tcp_send_auth(teavpn_cli_pkt *cli_pkt);
static void teavpn_client_tcp_handle_pkt_data(teavpn_srv_pkt *srv_pkt);

/**
 * @param teavpn_client_config *config
 * @return bool
 */
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *_config)
{
  #define srv_pkt ((teavpn_srv_pkt *)srv_pkt_arena)
  #define cli_pkt ((teavpn_cli_pkt *)cli_pkt_arena)

  int ret;
  uint16_t wait_fails = 0;
  pthread_t dispatcher_thread;
  char srv_pkt_arena[4096 + 1024], cli_pkt_arena[4096 + 1024];

  config = _config;

  if (!teavpn_client_tcp_init()) {
    ret = 1;
    goto close_net;
  }

  while (true) {

    debug_log(5, "Waiting for data...");
    if (teavpn_client_tcp_server_wait(srv_pkt) == -1) {
      wait_fails++;

      debug_log(5, "wait_fails got increased %d", wait_fails);

      if (wait_fails >= 1000) {
        debug_log(3, "Too many wait_fails");
        goto close_net;
      }

      continue;
    }

    switch (srv_pkt->type) {
      case SRV_PKT_AUTH_REQUIRED:
        debug_log(0, "Got SRV_PKT_AUTH_REQUIRED signal");
        if (!teavpn_client_tcp_send_auth(cli_pkt)) {
          debug_log(0, "Failed to send authentication data");
          goto close_net;
        }
        break;
      case SRV_PKT_AUTH_ACCEPTED:
        debug_log(0, "Authenticated!");
        break;
      // case SRV_PKT_IFACE_INFO:
      //   debug_log(3, "Got interface information");
      //   if (!teavpn_client_tcp_init_iface()) {
      //     goto close;
      //   }
      //   pthread_create(&dispatcher_thread, NULL,
      //     teavpn_server_tcp_handle_iface_read, NULL);
      //   pthread_detach(dispatcher_thread);
      //   break;
      case SRV_PKT_DATA:
        teavpn_client_tcp_handle_pkt_data(srv_pkt);
        break;
      default:
        debug_log(5, "Got unknown packet");
        break;
    }
  }

close_net:
  /* Close main TCP socket fd. */
  if (net_fd != -1) {
    close(net_fd);
  }
  return ret;

  #undef srv_pkt
  #undef cli_pkt
}

/**
 * @return bool
 */
static bool teavpn_client_tcp_init()
{
  struct sockaddr_in server_addr;

  /**
   * Create TCP socket.
   */
  debug_log(3, "Creating TCP socket...");
  net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(4, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(1, "Setting up socket file descriptor...");
  if (!teavpn_client_tcp_socket_setup()) {
    perror("Error setsockopt()");
    return false;
  }
  debug_log(4, "Socket file descriptor set up successfully");

  /**
   * Prepare server address and port.
   */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(config->socket.server_port);
  server_addr.sin_addr.s_addr = inet_addr(config->socket.server_addr);

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Connecting to %s:%d...", config->socket.server_addr, config->socket.server_port);
  if (connect(net_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) < 0) {
    perror("Error on connect");
    return false;
  }
  debug_log(0, "Connection established!");

  return true;
}

/**
 * @return bool
 */
static bool teavpn_client_tcp_socket_setup()
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }

  return true;
}

#define HANDLE_RECV do { \
  recv_ret = recv( \
    net_fd, &(((char *)srv_pkt)[total_recv_bytes]), \
    RECV_BUFFER, 0); \
  /* Error occured when calling recv. */ \
  RECV_ERROR_HANDLE(recv_ret, return -1); \
  /* Client has been disconnected. */ \
  RECV_ZERO_HANDLE(recv_ret, { \
    debug_log(5, \
      "Got zero byte read (assuming as disconnected from server)"); \
    return -1; \
  }); \
} while (0)


/**
 * @param register teavpn_srv_pkt *srv_pkt
 * @return int
 */
static int teavpn_client_tcp_server_wait(register teavpn_srv_pkt *srv_pkt)
{
  register ssize_t recv_ret;
  register uint16_t total_recv_bytes = 0;
  register uint16_t total_data_only = 0;

  while (total_recv_bytes < MIN_WAIT_RECV_BYTES) {
    HANDLE_RECV;
    total_recv_bytes += (uint16_t)recv_ret;
  }

  return (int)total_recv_bytes;
}

/**
 * @param teavpn_cli_pkt *cli_pkt
 * @return bool
 */
static bool teavpn_client_tcp_send_auth(teavpn_cli_pkt *cli_pkt)
{
  ssize_t slen;
  teavpn_cli_auth *auth;

  debug_log(0, "Authenticating...");

  cli_pkt->type = CLI_PKT_AUTH;
  cli_pkt->len = sizeof(teavpn_cli_auth);
  auth = (teavpn_cli_auth *)cli_pkt->data;

  strcpy(auth->username, config->auth.username);
  strcpy(auth->password, config->auth.password);

  slen = send(net_fd, cli_pkt, sizeof(teavpn_cli_pkt) + sizeof(teavpn_cli_auth), 0);
  SEND_ERROR_HANDLE(slen, return false;);

  debug_log(5, "Authentication data has been sent!");

  return true;
}

/**
 * @param teavpn_srv_pkt *srv_pkt
 * @return void
 */
static void teavpn_client_tcp_handle_pkt_data(teavpn_srv_pkt *srv_pkt)
{

}

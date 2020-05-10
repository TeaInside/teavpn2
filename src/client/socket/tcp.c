
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>
#include <teavpn2/global/data_struct.h>

#define SIGNAL_RECV_BUFFER 4096
#define RECV_ERROR_HANDLE(ret, act) \
  if (ret < 0) { \
    perror("Error recv()");  \
    act; \
  }
#define SEND_ERROR_HANDLE(ret, act) \
  if (ret < 0) { \
    perror("Error send()");  \
    act; \
  }

static int tun_fd;
static int net_fd;
static teavpn_srv_pkt *srv_pkt;
static teavpn_cli_pkt *cli_pkt;
static teavpn_client_config *config;
static struct sockaddr_in server_addr;

static bool teavpn_client_tcp_init();
static bool teavpn_client_tcp_socket_setup();
static bool teavpn_client_tcp_send_auth();
static int teavpn_client_tcp_wait_signal();
static void teavpn_client_tcp_init_iface();

/**
 * @param teavpn_client_config *config
 * @return bool
 */
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *_config)
{
  int ret;
  char arena1[8096], arena2[8096];

  config = _config;
  tun_fd = iinfo->tun_fd;
  srv_pkt = (teavpn_srv_pkt *)arena1;
  cli_pkt = (teavpn_cli_pkt *)arena2;

  if (!teavpn_client_tcp_init()) {
    ret = 1;
    goto close;
  }

  while (1) {
    
    if (teavpn_client_tcp_wait_signal() == -1) {
      goto close;
    }

    switch (srv_pkt->type) {
      case SRV_PKT_AUTH_REQUIRED:
        debug_log(3, "Got SRV_PKT_AUTH_REQUIRED signal");
        teavpn_client_tcp_send_auth();
        break;
      case SRV_PKT_AUTH_ACCEPTED:
        debug_log(3, "Authenticated!");
        break;
      case SRV_PKT_IFACE_INFO:
        debug_log(3, "Got interface information");
        teavpn_client_tcp_init_iface();
        break;
      default:
        debug_log(3, "Got invalid packet type");
        break;
    }

  }


close:
  /* Close main TCP socket fd. */
  if (net_fd != -1) {
    close(net_fd);
  }
  return ret;
}

/**
 * @return int
 */
static int teavpn_client_tcp_wait_signal()
{
  ssize_t rlen;

  /* Wait for signal. */
  rlen = recv(net_fd, srv_pkt, SIGNAL_RECV_BUFFER, 0);
  RECV_ERROR_HANDLE(rlen, return -1;);

  return rlen;
}

/**
 * @return void
 */
static void teavpn_client_tcp_init_iface()
{
  teavpn_srv_iface_info *iface = (teavpn_srv_iface_info *)srv_pkt->data;

  debug_log(0, "inet4: \"%s\"", iface->inet4);
  debug_log(0, "inet4_bc: \"%s\"", iface->inet4_bc);
}

/**
 * @return int
 */
static bool teavpn_client_tcp_send_auth()
{
  ssize_t slen;
  teavpn_cli_auth *auth;

  debug_log(1, "Authenticating...");

  cli_pkt->type = CLI_PKT_AUTH;
  cli_pkt->len = sizeof(teavpn_cli_auth);
  auth = (teavpn_cli_auth *)&(cli_pkt->data[0]);

  strcpy(auth->username, config->auth.username);
  strcpy(auth->password, config->auth.password);

  #define SIZE_TO_BE_SENT (sizeof(teavpn_cli_pkt) + sizeof(teavpn_cli_auth) - 1)

  slen = send(net_fd, cli_pkt, SIZE_TO_BE_SENT, 0);
  SEND_ERROR_HANDLE(slen, return false;);


  return true;
  #undef SIZE_TO_BE_SENT
}

/**
 * @return bool
 */
static bool teavpn_client_tcp_init()
{
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
  debug_log(3, "Setting up socket file descriptor...");
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

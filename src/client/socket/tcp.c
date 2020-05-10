
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
static teavpn_client_config *config;
static struct sockaddr_in server_addr;

static bool teavpn_client_tcp_init();
static bool teavpn_client_tcp_socket_setup();
static int teavpn_client_tcp_wait_signal(teavpn_srv_pkt *pkt);

/**
 * @param teavpn_client_config *config
 * @return bool
 */
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *_config)
{
  int ret;
  char buffer[2048] = {0};
  teavpn_srv_pkt *pkt = (teavpn_srv_pkt *)buffer;

  config = _config;
  tun_fd = iinfo->tun_fd;

  if (!teavpn_client_tcp_init()) {
    ret = 1;
    goto close;
  }

  teavpn_client_tcp_wait_signal(pkt);


close:
  /* Close main TCP socket fd. */
  if (net_fd != -1) {
    close(net_fd);
  }
  return ret;
}

/**
 * @param teavpn_srv_pkt *pkt
 * @return int
 */
static int teavpn_client_tcp_wait_signal(teavpn_srv_pkt *pkt)
{
  ssize_t rlen;

  /* Send wait for signal. */
  rlen = recv(net_fd, pkt, SIGNAL_RECV_BUFFER, 0);
  RECV_ERROR_HANDLE(rlen, return -1;);

  switch (pkt->type) {
    case SRV_PKT_AUTH_REQUIRED:
      debug_log(0, "SRV_PKT_AUTH_REQUIRED");
      break;
  }

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

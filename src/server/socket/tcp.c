
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

static int tun_fd;
static int net_fd;
static teavpn_server_config *config;
static struct sockaddr_in server_addr;

static bool teavpn_server_tcp_init();
static bool teavpn_server_tcp_socket_setup();

/**
 * @param teavpn_server_config *config
 * @return bool
 */
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *_config)
{
  int ret;
  config = _config;
  tun_fd = iinfo->tun_fd;

  if (!teavpn_server_tcp_init()) {
    ret = 1;
    goto close;
  }

  sleep(100);


close:
  /* Close main TCP socket fd. */
  if (net_fd != -1) {
    close(net_fd);
  }
  return ret;
}

static bool teavpn_server_tcp_init()
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
  if (!teavpn_server_tcp_socket_setup()) {
    return false;
  }
  debug_log(4, "Socket file descriptor set up successfully");

  /**
   * Prepare server bind address data.
   */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(config->socket.bind_port);
  server_addr.sin_addr.s_addr = inet_addr(config->socket.bind_addr);

  /**
   * Bind socket to corresponding address.
   */
  if (bind(net_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    error_log("Bind socket failed");
    perror("Bind failed");
    return false;
  }

  /**
   * Listen.
   */
  if (listen(net_fd, 3) < 0) {
    error_log("Listen socket failed");
    perror("Listen failed");
    return false;
  }

  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(4, "Listening on %s:%d...", config->socket.bind_addr, config->socket.bind_port);

  return true;
}

static bool teavpn_server_tcp_socket_setup()
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }
  return true;
}

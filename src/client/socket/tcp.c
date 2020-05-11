
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
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
#define READ_ERROR_HANDLE(ret, act) \
  if (ret < 0) { \
    perror("Error read()");  \
    act; \
  }
#define WRITE_ERROR_HANDLE(ret, act) \
  if (ret < 0) { \
    perror("Error write()");  \
    act; \
  }

static int tun_fd;
static int net_fd;
ssize_t signal_rlen;
static teavpn_srv_pkt *srv_pkt;
static teavpn_cli_pkt *cli_pkt;
static teavpn_client_config *config;
static struct sockaddr_in server_addr;

static bool teavpn_client_tcp_init();
static bool teavpn_client_tcp_socket_setup();
static bool teavpn_client_tcp_send_auth();
static int teavpn_client_tcp_wait_signal();
static bool teavpn_client_tcp_init_iface();
static void *teavpn_server_tcp_handle_iface_read(void *p);
static void teavpn_client_tcp_handle_pkt_data();

/**
 * @param teavpn_client_config *config
 * @return bool
 */
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *_config)
{
  int ret;
  char arena1[8096], arena2[8096];
  pthread_t client_iface_handler_thread;

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
        if (!teavpn_client_tcp_init_iface()) {
          goto close;
        }
        pthread_create(&client_iface_handler_thread, NULL,
          teavpn_server_tcp_handle_iface_read, NULL);
        pthread_detach(client_iface_handler_thread);
        break;
      case SRV_PKT_DATA:
        teavpn_client_tcp_handle_pkt_data();
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
 * @return void
 */
static void teavpn_client_tcp_handle_pkt_data()
{
  ssize_t wbytes;
  uint16_t total_signal_received = signal_rlen;
  uint16_t total_data_received;

  /* Make sure data length information is retrivied completely. */
  while (total_signal_received < sizeof(teavpn_srv_pkt)) {
    debug_log(5, "Re-receiving signal packet...");
    signal_rlen = recv(
      net_fd,
      &(((char *)srv_pkt)[total_signal_received]),
      SIGNAL_RECV_BUFFER,
      0
    );
    RECV_ERROR_HANDLE(signal_rlen, {});
    total_signal_received += (uint16_t)signal_rlen;
  }

  total_data_received = total_signal_received - (sizeof(teavpn_srv_pkt) - 1);

  /* Make sure data is retrivied completely. */
  while (total_data_received < srv_pkt->len) {
    debug_log(5, "Re-receiving packet...");
    signal_rlen = recv(
      net_fd,
      &(srv_pkt->data[total_data_received]),
      SIGNAL_RECV_BUFFER,
      0
    );
    RECV_ERROR_HANDLE(signal_rlen, {});
    total_data_received += (uint16_t)signal_rlen;
  }

  wbytes = write(tun_fd, srv_pkt->data, srv_pkt->len);
  WRITE_ERROR_HANDLE(wbytes, {});
  debug_log(5, "Write to tun_fd %ld bytes", wbytes);
}

#define TAP_READ_SIZE 4096

/**
 * @param void *p
 * @return void *
 */
static void *teavpn_server_tcp_handle_iface_read(void *p)
{
  char arena[4096 + 2048];
  ssize_t nread, slen;
  teavpn_cli_pkt *cli_pkt = (teavpn_cli_pkt *)arena;

  cli_pkt->type = CLI_PKT_DATA;

  while (1) {
    /**
     * Read from TUN/TAP.
     */
    nread = read(tun_fd, cli_pkt->data, TAP_READ_SIZE);
    READ_ERROR_HANDLE(nread, {});

    debug_log(5, "Read from tun_fd %ld bytes", nread);

    cli_pkt->len = (uint16_t)nread;

    slen = send(net_fd, cli_pkt, sizeof(teavpn_srv_pkt) + cli_pkt->len - 1, 0);
    SEND_ERROR_HANDLE(slen, {});
  }
}

/**
 * @return int
 */
static int teavpn_client_tcp_wait_signal()
{
  ssize_t tmp_rlen;
  signal_rlen = 0;

  /* Wait for signal. */
  while (signal_rlen < sizeof(teavpn_srv_pkt)) {
    tmp_rlen = recv(net_fd, srv_pkt, SIGNAL_RECV_BUFFER, 0);
    RECV_ERROR_HANDLE(tmp_rlen, return -1;);
    signal_rlen += tmp_rlen;
  }

  return signal_rlen;
}

/**
 * @return bool
 */
static bool teavpn_client_tcp_init_iface()
{
  teavpn_srv_iface_info *iface = (teavpn_srv_iface_info *)srv_pkt->data;

  debug_log(0, "inet4: \"%s\"", iface->inet4);
  debug_log(0, "inet4_bc: \"%s\"", iface->inet4_bc);

  strcpy(config->iface.inet4, iface->inet4);
  strcpy(config->iface.inet4_bcmask, iface->inet4_bc);

  debug_log(2, "Setting up teavpn network interface...");
  if (!teavpn_iface_init(&config->iface)) {
    error_log("Cannot set up teavpn network interface");
    return false;
  }

  return true;
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

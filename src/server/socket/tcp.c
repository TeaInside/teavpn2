
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define MAX_CLIENT_CHANNEL 10

typedef struct {
  bool is_online;
  int client_fd;
  pthread_t thread;
  struct sockaddr_in client_addr;
} teavpn_tcp_channel;

static int tun_fd;
static int net_fd;
static teavpn_server_config *config;
static struct sockaddr_in server_addr;

static int16_t online_chan = 0;
static int16_t free_chan_pos = 0; /* set -1 if channel is full. */
static teavpn_tcp_channel channels[MAX_CLIENT_CHANNEL];

static bool teavpn_server_tcp_init();
static int teavpn_server_tcp_accept();
static bool teavpn_server_tcp_socket_setup();
static void *teavpn_server_tcp_serve_client(teavpn_tcp_channel *chan);
static void teavpn_server_tcp_register_client(int client_fd, struct sockaddr_in *client_addr);

/**
 * @param teavpn_server_config *config
 * @return bool
 */
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *_config)
{
  int ret, client_fd;
  struct sockaddr_in client_addr;

  config = _config;
  tun_fd = iinfo->tun_fd;

  if (!teavpn_server_tcp_init()) {
    ret = 1;
    goto close;
  }

  while (1) {
    client_fd = teavpn_server_tcp_accept(&client_addr);
    teavpn_server_tcp_register_client(client_fd, &client_addr);
  }

close:
  /* Close main TCP socket fd. */
  if (net_fd != -1) {
    close(net_fd);
  }
  return ret;
}

/**
 * @param struct sockaddr_in *client_addr
 * @return int
 */
static int teavpn_server_tcp_accept(struct sockaddr_in *client_addr)
{
  int client_fd;
  socklen_t rlen = sizeof(struct sockaddr_in);

  /**
   * Accepting client connection.
   */
  client_fd = accept(net_fd, (struct sockaddr *)client_addr, &rlen);
  if (client_fd < 0) {
    debug_log(1, "An error occured when accepting connection!");
    perror("accept()");
  }

  debug_log(2, "Accepting client (%s:%d)...",
    inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));

  return client_fd;
}

/**
 * @param int client_fd
 * @param struct sockaddr_in *client_addr
 * @return void
 */
static void teavpn_server_tcp_register_client(register int client_fd, struct sockaddr_in *client_addr)
{

  /* Save client_fd. */
  channels[free_chan_pos].client_fd = client_fd;

  /* Copy client_addr information to the channel. */
  memcpy(&(channels[free_chan_pos].client_addr), client_addr, sizeof(struct sockaddr_in));

  /* Create a new thread to serve the client. */
  pthread_create(&(channels[free_chan_pos].thread), NULL,
    (void * (*)(void *))teavpn_server_tcp_serve_client,
    (void *)&(channels[free_chan_pos]));

  /* Detach thread, let the thread do the job. */
  pthread_detach(channels[free_chan_pos].thread);

  free_chan_pos = -1;

prepare_channel:
  /* Prepare for free channel. */
  for (register uint16_t i = 0; i < MAX_CLIENT_CHANNEL; i++) {
    if (!channels[i].is_online) {
      free_chan_pos = i;
      break;
    }
  }

  /* Don't accept new connection if channel is full. */
  if (free_chan_pos == -1) {
    sleep(1);
    goto prepare_channel;
  }
}

/**
 * @param teavpn_tcp_channel *chan
 */
static void *teavpn_server_tcp_serve_client(teavpn_tcp_channel *chan)
{
  sleep(100);
}

/**
 * @return bool
 */
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

  /* Init channels with zero bytes. */
  memset(channels, 0, sizeof(channels));

  return true;
}

/**
 * @return bool
 */
static bool teavpn_server_tcp_socket_setup()
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }
  return true;
}

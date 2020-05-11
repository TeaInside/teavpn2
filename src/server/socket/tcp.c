
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
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define MAX_CLIENT_CHANNEL 10
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

typedef struct {
  bool is_online;
  bool authenticated;
  pthread_t thread;
  int client_fd;
  void *misc_arena;
  struct {
    char *addr;
    uint8_t addr_len;
    uint16_t port;
  } cvt;
  struct {
    char *username;
    uint8_t username_len;
  } user;
  teavpn_srv_pkt *srv_pkt;
  teavpn_cli_pkt *cli_pkt;
  ssize_t signal_rlen;
  ssize_t slen;
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
static void *teavpn_server_tcp_handle_iface(void *p);
static void teavpn_server_tcp_register_client(int client_fd, struct sockaddr_in *client_addr);

/**
 * Functions that are called by threads.
 */
static bool teavpn_server_tcp_auth(teavpn_tcp_channel *chan);
static int teavpn_server_tcp_wait_signal(teavpn_tcp_channel *chan);
static void *teavpn_server_tcp_serve_client(teavpn_tcp_channel *chan);
static bool teavpn_server_tcp_send_iface_info(teavpn_tcp_channel *chan);
static void teavpn_server_tcp_handle_client_pkt_data(teavpn_tcp_channel *chan);

/**
 * @param teavpn_server_config *config
 * @return bool
 */
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *_config)
{
  int ret, client_fd;
  struct sockaddr_in client_addr;
  pthread_t server_iface_handler;

  config = _config;
  tun_fd = iinfo->tun_fd;

  if (!teavpn_server_tcp_init()) {
    ret = 1;
    goto close;
  }

  pthread_create(&server_iface_handler, NULL,
    teavpn_server_tcp_handle_iface, NULL);

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
  channels[free_chan_pos].client_addr = *client_addr;
  channels[free_chan_pos].is_online = true;

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
 * @return bool
 */
static bool teavpn_server_tcp_auth(teavpn_tcp_channel *chan)
{
  ssize_t slen, rlen;
  uint8_t password_len;
  teavpn_srv_pkt *srv_pkt = chan->srv_pkt;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  teavpn_cli_auth *auth = (teavpn_cli_auth *)cli_pkt->data;

  if (cli_pkt->len != sizeof(teavpn_cli_auth)) {
    debug_log(2, "Invalid packet from client");
    goto auth_reject;
  }

  /* Check password. */
  {
    int file_fd;
    ssize_t frlen;
    bool reject = false;
    char auth_file[512], *password = auth_file;

    sprintf(auth_file, "%s/users/%s/password", config->data_dir, auth->username);
    file_fd = open(auth_file, O_RDONLY);

    if (file_fd < 0) {
      debug_log(2, "Invalid username or password!");
      goto auth_reject; /* No need to close fd, since it fails. */
    }

    password_len = (uint8_t)strlen(auth->password);
    frlen = read(file_fd, password, password_len);
    if (frlen < 0) {
      reject = true;
      debug_log(2, "Cannot read password from file");
      goto close_file_fd;
    }
    password[password_len] = '\0';

    reject = !(
      (password_len == ((uint8_t)frlen)) && (!strcmp(password, auth->password))
    );

close_file_fd:
    close(file_fd);
    if (reject) goto auth_reject;
  }

  debug_log(2, "Auth OK");
  srv_pkt->type = SRV_PKT_AUTH_ACCEPTED;
  chan->slen = send(chan->client_fd, srv_pkt, sizeof(teavpn_srv_pkt), 0);
  SEND_ERROR_HANDLE(chan->slen, return false;);

  /* Allocate some arena to store username. */
  chan->user.username = (char *)chan->misc_arena;
  strcpy(chan->user.username, auth->username);
  chan->user.username_len = strlen(chan->user.username);

  /* Increase arena pointer. */
  chan->misc_arena = (void *)( ((char *)chan->misc_arena) + chan->user.username_len + 2);

  return true;

auth_reject:
  srv_pkt->type = SRV_PKT_AUTH_REJECTED;
  chan->slen = send(chan->client_fd, srv_pkt, sizeof(teavpn_srv_pkt), 0);
  SEND_ERROR_HANDLE(chan->slen, return false;);
  return false;
}

/**
 * @param teavpn_tcp_channel *chan
 * @return bool
 */
static bool teavpn_server_tcp_send_iface_info(teavpn_tcp_channel *chan)
{
  int file_fd;
  ssize_t frlen;
  struct stat file_stat;
  char arena[512], *inet4_file = arena, *inet4, *inet4_bc = NULL;
  teavpn_srv_pkt *srv_pkt = chan->srv_pkt;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  teavpn_srv_iface_info *iface = (teavpn_srv_iface_info *)srv_pkt->data;
  
  srv_pkt->type = SRV_PKT_IFACE_INFO;
  sprintf(inet4_file, "%s/users/%s/inet4", config->data_dir, chan->user.username);
  file_fd = open(inet4_file, O_RDONLY);
  if (file_fd < 0) {
    perror("open()");
    debug_log(2, "Cannot open inet4 file to serve %s:%d", chan->cvt.addr, chan->cvt.port);
    return false;
  }

  if (fstat(file_fd, &file_stat) < 0) {
    perror("fstat()");
    debug_log(2, "Cannot stat inet4 file to serve %s:%d", chan->cvt.addr, chan->cvt.port);
    return false; 
  }

  frlen = read(file_fd, arena, file_stat.st_size);
  if (frlen < 0) {
    perror("read()");
    debug_log(2, "Cannot read inet4 file to serve %s:%d", chan->cvt.addr, chan->cvt.port);
    return false;
  }

  arena[frlen] = '\0';

  { 
    register ssize_t i;
    inet4 = arena;
    for (i = 0; i < frlen; i++) {
      if (i >= 255) {
        break;
      }
      if (inet4[i] == ' ') {
        inet4[i] = '\0';
        inet4_bc = &(inet4[i + 1]);
        break;
      }
    }

    if (inet4_bc == NULL) {
      goto invalid_inet4_file;
    }
  }

  strcpy(iface->inet4, inet4);
  strcpy(iface->inet4_bc, inet4_bc);

  #define SIZE_TO_SEND (sizeof(teavpn_srv_pkt) + sizeof(teavpn_srv_iface_info))

  chan->slen = send(chan->client_fd, srv_pkt, SIZE_TO_SEND, 0);
  SEND_ERROR_HANDLE(chan->slen, return false;);

  chan->authenticated = true;
  return true;

invalid_inet4_file:
  debug_log(0, "Invalid inet4 file for user %s", chan->user.username);
  return false;
}

/**
 * @param teavpn_tcp_channel *chan
 * @return int
 */
static int teavpn_server_tcp_wait_signal(teavpn_tcp_channel *chan)
{
  /* Wait for signal. */
  chan->signal_rlen = recv(chan->client_fd, chan->cli_pkt, SIGNAL_RECV_BUFFER, 0);
  RECV_ERROR_HANDLE(chan->signal_rlen, return -1;);
}

/**
 * @param teavpn_tcp_channel *chan
 * @return void *
 */
static void *teavpn_server_tcp_serve_client(teavpn_tcp_channel *chan)
{
  int ret;
  char rd_client_info_arena[64] = {0},
    misc_arena[256] = {0},
    cli_pkt_arena[SIGNAL_RECV_BUFFER + 1024] = {0},
    srv_pkt_arena[SIGNAL_RECV_BUFFER + 1024] = {0};

  /* Store readable client address and port info. */
  strcpy(rd_client_info_arena, inet_ntoa(chan->client_addr.sin_addr));
  chan->cvt.addr = rd_client_info_arena;
  chan->cvt.port = ntohs(chan->client_addr.sin_port);
  chan->cvt.addr_len = strlen(chan->cvt.addr);

  /* Allocate arena. */
  chan->srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;
  chan->cli_pkt = (teavpn_cli_pkt *)cli_pkt_arena;
  chan->misc_arena = (void *)misc_arena;

  /* Send auth required signal after connection established. */
  chan->srv_pkt->type = SRV_PKT_AUTH_REQUIRED;
  chan->slen = send(chan->client_fd, chan->srv_pkt, sizeof(teavpn_srv_pkt), 0);
  SEND_ERROR_HANDLE(chan->slen, return false;);

  /* Event loop. */
  while (1) {

    if (teavpn_server_tcp_wait_signal(chan) == -1) {
      debug_log(0, "Error when waiting for signal from %s:%d", chan->cvt.addr, chan->cvt.port);
      continue;
    }

    switch (chan->cli_pkt->type) {
      case CLI_PKT_AUTH:
        if (!teavpn_server_tcp_auth(chan)) {
          debug_log(3, "Auth failed from %s:%d!", chan->cvt.addr, chan->cvt.port);
          goto close_fd;
        }

        if (!teavpn_server_tcp_send_iface_info(chan)) {
          goto close_fd;
        }
        break;
      case CLI_PKT_DATA:
        teavpn_server_tcp_handle_client_pkt_data(chan);
        break;
    }

  }

close_fd:
  chan->is_online = false;
  debug_log(2, "Closing connection from %s:%d", chan->cvt.addr, chan->cvt.port);
  close(chan->client_fd);
  return NULL;
}

/**
 * @param teavpn_tcp_channel *chan
 * @return void
 */
void teavpn_server_tcp_handle_client_pkt_data(teavpn_tcp_channel *chan)
{
  ssize_t wbytes;
  teavpn_cli_pkt *cli_pkt = chan->cli_pkt;
  uint16_t total_received = chan->signal_rlen;

  while (total_received < cli_pkt->len) {
    chan->signal_rlen = recv(chan->client_fd, (cli_pkt->data + total_received), SIGNAL_RECV_BUFFER, 0);
    RECV_ERROR_HANDLE(chan->signal_rlen, {});
  }

  wbytes = write(tun_fd, cli_pkt->data, cli_pkt->len);
  WRITE_ERROR_HANDLE(wbytes, {});
  debug_log(5, "Write to tun_fd %ld bytes", wbytes);
}

#define TAP_READ_SIZE 2048

/**
 * @param void *p
 * @return void *
 */
static void *teavpn_server_tcp_handle_iface(void *p)
{
  char arena[4096];
  ssize_t nread, slen;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)arena;

  srv_pkt->type = SRV_PKT_DATA;

  while (1) {
    /**
     * Read from TUN/TAP.
     */
    nread = read(tun_fd, srv_pkt->data, TAP_READ_SIZE);
    READ_ERROR_HANDLE(nread, {});

    debug_log(5, "Read from tun_fd %ld bytes", nread);

    srv_pkt->len = (uint16_t)nread;

    for (register int16_t i = 0; i < MAX_CLIENT_CHANNEL; i++) {
      if (channels[i].is_online && channels[i].authenticated) {
        slen = send(channels[i].client_fd, srv_pkt,
          sizeof(teavpn_srv_pkt) + srv_pkt->len - 1, 0);
        SEND_ERROR_HANDLE(slen, {});
      }
    }
  }
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

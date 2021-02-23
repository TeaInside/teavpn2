
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <teavpn2/server/auth.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define TCP_CHANNEL_AMOUNT 10
#define PKT_ARENA_SIZE     8192

#define READ_TUN_ERR_MAX   1024
#define WRITE_TUN_ERR_MAX  1024

#define READ_TUN_BUFFER (PKT_ARENA_SIZE - SRV_PKT_RSIZE(0))
#define RECV_NET_BUFFER (PKT_ARENA_SIZE - CLI_PKT_RSIZE(0))

#define ZERO_HANDLE(RETVAL, ACT) do { if (RETVAL == 0) { ACT; } } while (0)
#define ERR_HANDLE(FUNC, RETVAL, ACT) do { if (RETVAL == -1) { perror("Error "#FUNC); ACT; } } while (0)

#define SEND_ERR_HANDLE(RETVAL, ACT) do { ERR_HANDLE(send(), RETVAL, ACT); } while (0)
#define RECV_ERR_HANDLE(RETVAL, ACT) do { ERR_HANDLE(recv(), RETVAL, ACT); } while (0)
#define READ_ERR_HANDLE(RETVAL, ACT) do { ERR_HANDLE(read(), RETVAL, ACT); } while (0)

#define READ_MAX_ERR(MSTATE, ACT) \
  if (MSTATE->read_tun_err >= READ_TUN_ERR_MAX) { \
    debug_log(0, "Reached the max numner of read error"); \
    teavpn_server_tcp_stop_all(MSTATE); \
    ACT; \
  }

static void teavpn_server_tcp_stop_all(server_tcp_mstate *mstate);
static inline bool teavpn_server_tcp_init(server_tcp_mstate *mstate);
static inline bool teavpn_server_tcp_socket_setup(int net_fd);
static inline void teavpn_server_tcp_accept(server_tcp_mstate *mstate);
static int16_t teavpn_server_tcp_free_chan_observe(server_tcp_mstate *mstate);
static inline void teavpn_server_tcp_full_chan_act(server_tcp_mstate *mstate);
static inline void teavpn_server_tcp_handle_iface_data(server_tcp_mstate *mstate);

/**
 * @param iface_info *iinfo
 * @param teavpn_server_config *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *config)
{
  int ret = 0, rc;
  server_tcp_mstate mstate;

  /* Initialize mstate values. */
  bzero(&mstate, sizeof(server_tcp_mstate));
  mstate.fci = 0;
  mstate.iinfo = iinfo;
  mstate.config = config;
  mstate.stop_all = false;
  mstate.tun_fd = iinfo->tun_fd;
  config->mstate = (void *)&mstate;
  mstate.pipe_fd[0] = -1;
  mstate.pipe_fd[1] = -1;


  /* Allocate heap for channels and fds. */
  mstate.channels = (tcp_channel *)malloc(TCP_CHANNEL_AMOUNT * sizeof(tcp_channel));
  mstate.fds = (struct pollfd *)malloc(TCP_CHANNEL_AMOUNT * sizeof(struct pollfd));
  bzero(mstate.fds,  TCP_CHANNEL_AMOUNT * sizeof(struct pollfd));
  bzero(mstate.channels, TCP_CHANNEL_AMOUNT * sizeof(tcp_channel));


  /**
   * Init TCP socket.
   */
  if (!teavpn_server_tcp_init(&mstate)) {
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


  /* Add TCP socket fd to fds. */
  mstate.fds[0].fd = mstate.net_fd;
  mstate.fds[0].events = POLLIN;


  /* Add tunnel fd to fds. */
  mstate.fds[1].fd = mstate.tun_fd;
  mstate.fds[1].events = POLLIN;


  /* Add pipe fd to fds. */
  mstate.fds[2].fd = mstate.pipe_fd[0];
  mstate.fds[2].events = POLLIN;


  mstate.nfds = 3;
  mstate.timeout = 3000;


  /**
   * Master event loop.
   */
  while (true) {

    rc = poll(mstate.fds, mstate.nfds, mstate.timeout);


    /* Poll reached timeout. */
    if (rc == 0) {
      goto end_loop;
    }


    /* Accept new client. */
    if (mstate.fds[0].revents == POLLIN) {
      teavpn_server_tcp_accept(&mstate);
    }


    /* Handle server's tunnel interface data. */
    if (mstate.fds[1].revents == POLLIN) {
      teavpn_server_tcp_handle_iface_data(&mstate);
    }


    /* Handle pipe. */
    if (mstate.fds[2].revents == POLLIN) {
      goto end_loop;
    }

end_loop:
    if (mstate.stop_all) {
      debug_log(0, "Got stop_all signal");
      goto close_conn;
    }
  }


close_conn:

  /* Close online client fd. */
  for (register int16_t i = 0; i < TCP_CHANNEL_AMOUNT; i++) {
    if (mstate.channels[i].is_online) {
      close(mstate.channels[i].fd);
    }
  }

  if (mstate.net_fd != -1) {
    close(mstate.net_fd);
  }

  if (mstate.pipe_fd[0] != -1) {
    close(mstate.pipe_fd[0]);
  }

  if (mstate.pipe_fd[1] != -1) {
    close(mstate.pipe_fd[1]);
  }

  /* Release heap. */
  free(mstate.fds);
  free(mstate.channels);

  return ret;
}


/** 
 * @param server_tcp_mstate *mstate
 * @return bool
 */
static void teavpn_server_tcp_stop_all(server_tcp_mstate *mstate)
{
  int write_ret;
  mstate->stop_all = true;
  write_ret = write(mstate->pipe_fd[1], (char *)"11111111", 8);
  if (write_ret < 0) {
    perror("Error write()");
    error_log("Error writing to pipe");
  }
}


/** 
 * @param server_tcp_mstate *mstate
 * @return bool
 */
static inline bool teavpn_server_tcp_init(server_tcp_mstate *mstate)
{
  /**
   * Create TCP socket (SOCK_STREAM).
   */
  debug_log(0, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (mstate->net_fd < 0) {
    perror("Socket creation failed");
    error_log("Cannot create TCP socket");
    return false;
  }
  debug_log(0, "TCP socket created successfully");


  /**
   * Setup TCP socket.
   */
  debug_log(0, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(mstate->net_fd)) {
    return false;
  }
  debug_log(0, "Socket file descriptor set up successfully");


  /**
   * Prepare server bind address data.
   */
  bzero(&(mstate->server_addr), sizeof(struct sockaddr_in));
  mstate->server_addr.sin_family = AF_INET;
  mstate->server_addr.sin_port = htons(mstate->config->socket.bind_port);
  mstate->server_addr.sin_addr.s_addr = inet_addr(mstate->config->socket.bind_addr);


  /**
   * Bind socket to address.
   */
  if (bind(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(mstate->server_addr)) < 0) {
    perror("Bind failed");
    error_log("Bind socket failed");
    return false;
  }


  /**
   * Listen socket.
   */
  if (listen(mstate->net_fd, 32) < 0) {
    perror("Listen failed");
    error_log("Listen socket failed");
    return false;
  }


  /**
   * Ignore SIGPIPE
   */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Listening on %s:%d...", mstate->config->socket.bind_addr, mstate->config->socket.bind_port);

  return true;
}


/**
 * @param int net_fd
 * @return bool
 */
static inline bool teavpn_server_tcp_socket_setup(int net_fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN) \
    if (setsockopt(net_fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) { \
      perror("setsockopt()"); \
      error_log("setsockopt() error"); \
      return false; \
    }

  SET_SOCK_OPT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}


/**
 * @param server_tcp_mstate *mstate
 * @return void
 */
static inline void teavpn_server_tcp_accept(server_tcp_mstate *mstate)
{
  register tcp_channel *chan;
  register tcp_channel *channels = mstate->channels;
  socklen_t rlen = sizeof(struct sockaddr_in);

  if (mstate->fci == -1) {
    if (teavpn_server_tcp_free_chan_observe(mstate) == -1) {
      debug_log(2, "Channel is full, cannot handle more client");
      teavpn_server_tcp_full_chan_act(mstate);
      return;
    }
  }

  chan = &(mstate->channels[mstate->fci]);
  chan->fd = accept(mstate->net_fd, (struct sockaddr *)&(chan->saddr), &rlen);
  if (chan->fd < 0) {

    if (errno == EWOULDBLOCK) {
      debug_log(8, "accept() got EWOULDBLOCK");
      return;
    }

    perror("accept()");
    error_log("Error accepting (full chan act)");
    return;
  }

  mstate->online_chan++;
}


/**
 * @param server_tcp_mstate *mstate
 * @return int16_t
 */
static int16_t teavpn_server_tcp_free_chan_observe(server_tcp_mstate *mstate)
{
  register tcp_channel *channels = mstate->channels;

  for (register int16_t i = 0; i < TCP_CHANNEL_AMOUNT; i++) {
    if (!channels[i].is_online) {
      mstate->fci = i;
      return i;
    }
  }

  mstate->fci = -1;
  return -1;
}


/**
 * @param server_tcp_mstate *mstate
 * @return void
 */
static inline void teavpn_server_tcp_full_chan_act(server_tcp_mstate *mstate)
{
  teavpn_srv_pkt srv_pkt;
  int client_fd, send_ret;
  struct sockaddr_in saddr;
  socklen_t rlen = sizeof(struct sockaddr_in);

  client_fd = accept(mstate->net_fd, (struct sockaddr *)&saddr, &rlen);
  if (client_fd < 0) {

    if (errno == EWOULDBLOCK) {
      debug_log(8, "accept() got EWOULDBLOCK");
      return;
    }

    perror("accept()");
    error_log("Error accepting (full chan act)");
    return;
  }

  srv_pkt.type = SRV_PKT_CHAN_IS_FULL;
  srv_pkt.len  = 0;

  debug_log(0, "Sending SRV_PKT_CHAN_IS_FULL to %s:%d...",
    inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

  send_ret = send(client_fd, &srv_pkt, SRV_PKT_RSIZE(0), MSG_DONTWAIT);
  SEND_ERR_HANDLE(send_ret, {});

  close(client_fd);
}


/**
 * @param server_tcp_mstate *mstate
 * @return void
 */
static inline void teavpn_server_tcp_handle_iface_data(server_tcp_mstate *mstate)
{
  int read_ret;
  char srv_pkt_arena[PKT_ARENA_SIZE];
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;

  read_ret = read(mstate->tun_fd, srv_pkt->data, READ_TUN_BUFFER);
  READ_ERR_HANDLE(read_ret, {
    mstate->read_tun_err++;
    READ_MAX_ERR(mstate, {});
  });
}

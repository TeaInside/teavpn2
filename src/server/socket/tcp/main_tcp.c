
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <teavpn2/server/auth.h>
#include <teavpn2/global/iface.h>
#include <teavpn2/server/common.h>
#include <teavpn2/server/socket/tcp.h>

#define MAX_ERROR_RECV 1024
#define MAX_ERROR_SEND 1024
#define MAX_ERROR_READ 1024
#define MAX_ERROR_WRITE 1024
#define MAX_ERROR_ACCEPT 1024
#define TCP_CHANNEL_AMOUNT 10
#define PACKET_ARENA_SIZE 5120
#define CLI_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_cli_pkt) - 1) + ADD_SIZE)
#define SRV_PKT_RSIZE(ADD_SIZE) ((sizeof(teavpn_srv_pkt) - 1) + ADD_SIZE)
#define SERVER_RECV_BUFFER (PACKET_ARENA_SIZE - CLI_PKT_RSIZE(0))
#define SERVER_READ_BUFFER (PACKET_ARENA_SIZE - SRV_PKT_RSIZE(0))
#define FUNC_ZERO_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL == 0) { ACTION; } } while (0)
#define FUNC_ERROR_HANDLE(FUNC, RETVAL, ACTION) do { if (RETVAL < 0) { perror("Error "#FUNC); ACTION; } } while (0)
#define M_RECV_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(recv(), RETVAL, ACTION)
#define M_SEND_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(send(), RETVAL, ACTION)
#define M_READ_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(read(), RETVAL, ACTION)
#define M_WRITE_ZERO_HANDLE(RETVAL, ACTION) FUNC_ZERO_HANDLE(write(), RETVAL, ACTION)
#define M_RECV_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(recv(), RETVAL, ACTION)
#define M_SEND_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(send(), RETVAL, ACTION)
#define M_READ_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(read(), RETVAL, ACTION)
#define M_WRITE_ERROR_HANDLE(RETVAL, ACTION) FUNC_ERROR_HANDLE(write(), RETVAL, ACTION)
#define RCP chan->saddr_r, chan->sport_r
#define RC "[%s:%d] "

static void teavpn_server_tcp_stop_all(server_tcp_mstate *__restrict__ mstate);
inline static bool teavpn_server_tcp_init(server_tcp_mstate *mstate);
inline static bool teavpn_server_tcp_socket_setup(int net_fd);
inline static int teavpn_server_tcp_accept(server_tcp_mstate *__restrict__ mstate);
inline static void teavpn_server_tcp_client_auth(tcp_channel *chan);
inline static int16_t teavpn_server_tcp_extra_recv(tcp_channel *chan);
inline static void teavpn_server_tcp_handle_client_data(tcp_channel *chan);
inline static void teavpn_server_tcp_client_accept_init(server_tcp_mstate *__restrict__ mstate, tcp_channel *__restrict__ chan);
inline static void teavpn_server_tcp_resolve_free_channel(server_tcp_mstate *__restrict__ mstate);
static void teavpn_server_tcp_accept_and_drop(server_tcp_mstate *__restrict__ mstate);
inline static void teavpn_server_tcp_tun_handle(server_tcp_mstate *__restrict__ mstate);

/**
 * @param iface_info *iinfo
 * @param teavpn_server_config *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *config)
{
  nfds_t nfds;
  char buf_pipe[8];
  server_tcp_mstate mstate;
  tcp_channel channels[TCP_CHANNEL_AMOUNT];
  struct pollfd fds[TCP_CHANNEL_AMOUNT + 4];
  int ret = 0, rc, timeout, accept_fd, errsv;

  bzero(fds, sizeof(fds));
  bzero(&mstate, sizeof(mstate));
  bzero(channels, sizeof(channels));

  mstate.fci = 0;
  mstate.fds = fds;
  mstate.iinfo = iinfo;
  mstate.config = config;
  mstate.channels = channels;
  mstate.tun_fd = iinfo->tun_fd;

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
  fds[0].fd = mstate.net_fd;
  fds[0].events = POLLIN;

  /* Add tunnel fd to fds. */
  fds[1].fd = mstate.tun_fd;
  fds[1].events = POLLIN;

  /* Add pipe fd to fds. */
  fds[2].fd = mstate.pipe_fd[0];
  fds[2].events = POLLIN;

  nfds = 3;
  timeout = 5;


  /**
   * Master event loop.
   */
  while (true) {
    rc = poll(fds, nfds, timeout);

    /* Poll reached timeout. */
    if (rc == 0) {
      goto end_loop;
    }


    /* Accept new client. */
    if (fds[0].revents == POLLIN) {
      teavpn_server_tcp_accept(&mstate);
    }



    /* Handle server's tunnel interface data. */
    if (fds[1].revents == POLLIN) {
      teavpn_server_tcp_tun_handle(&mstate);
    }



    /* Traverse clients' fd. */
    for (register int16_t i = 3; i < nfds; i++) {
      if (fds[i].revents == POLLIN) {
      }
    }



end_loop:
    if (mstate.stop_all) {
      debug_log(0, "Got stop_all signal");
      debug_log(0, "Stopping everything...");
      goto close_conn;
    }
  }



close_conn:
  if (mstate.net_fd != -1) {
    close(mstate.net_fd);
  }
  if (mstate.pipe_fd[0] != -1) {
    close(mstate.pipe_fd[0]);
  }
  if (mstate.pipe_fd[1] != -1) {
    close(mstate.pipe_fd[1]);
  }
  return ret;
}

/**
 * @param server_tcp_mstate *mstate
 * @return void
 */
static void teavpn_server_tcp_stop_all(server_tcp_mstate *__restrict__ mstate)
{
  ssize_t write_ret;
  mstate->stop_all = true;
  write_ret = write(mstate->pipe_fd[1], (void *)"12345678", 8);
  if (write_ret < 0) {
    perror("stop all write()");
  }
}

/**
 * @param server_tcp_mstate *mstate
 * @return bool
 */
static bool teavpn_server_tcp_init(server_tcp_mstate *mstate)
{
  int on = 1;
  char *priv_ip_c = (char *)&(mstate->s_ip);
  priv_ip_c[0] = atoi(mstate->config->iface.inet4);
  register uint8_t i = 0;
  register uint8_t j = 1;
  for (; i < strlen(mstate->config->iface.inet4); i++) {
    if (mstate->config->iface.inet4[i] == '.') {
      priv_ip_c[j++] = atoi(&(mstate->config->iface.inet4[i + 1]));
    }
  }

  debug_log(7, "server_ip: %d.%d.%d.%d",
    ((mstate->s_ip >> 0) & 0xff),
    ((mstate->s_ip >> 8) & 0xff),
    ((mstate->s_ip >> 16) & 0xff),
    ((mstate->s_ip >> 24) & 0xff)
  );

  /**
   * Create TCP socket.
   */
  debug_log(2, "Creating TCP socket...");
  mstate->net_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (mstate->net_fd < 0) {
    error_log("Cannot create TCP socket");
    perror("Socket creation failed");
    return false;
  }
  debug_log(2, "TCP socket created successfully");

  /**
   * Setup TCP socket.
   */
  debug_log(2, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(mstate->net_fd)) {
    return false;
  }
  if (ioctl(mstate->net_fd, FIONBIO, (char *)&on) < 0) {
    perror("ioctl() failed");
    return false;
  }
  debug_log(2, "Socket file descriptor set up successfully");

  /**
   * Prepare server bind address data.
   */
  bzero(&(mstate->server_addr), sizeof(struct sockaddr_in));
  mstate->server_addr.sin_family = AF_INET;
  mstate->server_addr.sin_port = htons(mstate->config->socket.bind_port);
  mstate->server_addr.sin_addr.s_addr = inet_addr(mstate->config->socket.bind_addr);

  /**
   * Bind socket to corresponding address.
   */
  if (bind(mstate->net_fd, (struct sockaddr *)&(mstate->server_addr), sizeof(mstate->server_addr)) < 0) {
    error_log("Bind socket failed");
    perror("Bind failed");
    return false;
  }

  /**
   * Listen.
   */
  if (listen(mstate->net_fd, 3) < 0) {
    error_log("Listen socket failed");
    perror("Listen failed");
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
inline static bool teavpn_server_tcp_socket_setup(int net_fd)
{
  int optval = 1;
  if (setsockopt(net_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
    perror("setsockopt()");
    return false;
  }
  return true;
}

/** 
 * @param server_tcp_mstate *mstate
 * @return int
 */
inline static int teavpn_server_tcp_accept(server_tcp_mstate *__restrict__ mstate)
{
  register tcp_channel *chan;
  socklen_t rlen = sizeof(struct sockaddr_in);

  /* Check available channel. */
  if (mstate->fci == -1) {

    /* Try to resolve available channel. */
    teavpn_server_tcp_resolve_free_channel(mstate);

    if (mstate->fci != -1) {
      debug_log(0, "Couldn't handle more client, channel is full.");
      teavpn_server_tcp_accept_and_drop(mstate);
      return -1;
    }
  }

  chan = &(mstate->channels[mstate->fci]);

  chan->fd = accept(mstate->net_fd, (struct sockaddr *)&(chan->saddr), &rlen);

  if (chan->fd < 0) {
    if (errno != EWOULDBLOCK) {
      perror("accept() failed");
      return -1;
    }
  }

  teavpn_server_tcp_client_accept_init(mstate, chan);
  teavpn_server_tcp_resolve_free_channel(mstate);

  return chan->fd;
}

/**
 * @param server_tcp_mstate *mstate
 * @param tcp_channel *chan
 * @return void
 */
inline static void teavpn_server_tcp_client_accept_init(server_tcp_mstate *__restrict__ mstate, tcp_channel *__restrict__ chan)
{
  /* Set channel state. */
  chan->stop = false;
  chan->is_online = true;
  chan->is_authenticated = false;

  /* Copy client readable address and port. */
  strncpy(chan->saddr_r, inet_ntoa(chan->saddr.sin_addr), 32);
  chan->saddr_r_len = strlen(chan->saddr_r);
  chan->sport_r = ntohs(chan->saddr.sin_port);

  /* Reset error counter. */
  chan->error_recv_count = 0;
  chan->error_send_count = 0;

  /* Plug mstate pointer to client channel. */
  chan->mstate = mstate;
}

/** 
 * @param server_tcp_mstate *mstate
 * @return void
 */
inline static void teavpn_server_tcp_resolve_free_channel(server_tcp_mstate *__restrict__ mstate)
{
  register int16_t i;
  register tcp_channel *channels = mstate->channels;

  for (i = 0; i < TCP_CHANNEL_AMOUNT; i++) {
    if (!channels[i].is_online) {
      mstate->fci = i;
      break;
    }
  }
}

/** 
 * @param server_tcp_mstate *mstate
 * @return void
 */
static void teavpn_server_tcp_accept_and_drop(server_tcp_mstate *__restrict__ mstate)
{
  register int client_fd;
  teavpn_srv_pkt srv_pkt;
  struct sockaddr_in saddr;
  socklen_t rlen = sizeof(struct sockaddr_in);

  client_fd = accept(mstate->net_fd, (struct sockaddr *)&saddr, &rlen);
  if (client_fd < 0) {
    if (errno != EWOULDBLOCK) {
      perror("accept() failed");
      goto close_conn;
    }
  }

  debug_log(2, "Sending SRV_PKT_CHAN_IS_FULL to %s:%d", inet_ntoa(saddr.sin_addr), ntohs(saddr.sin_port));

  srv_pkt.type = SRV_PKT_CHAN_IS_FULL;
  srv_pkt.len  = 0;
  if (send(client_fd, &srv_pkt, SRV_PKT_RSIZE(0), MSG_DONTWAIT) < 0) {
    perror("send()");
  }

close_conn:
  close(client_fd);
}

/** 
 * @param server_tcp_mstate *mstate
 * @return void
 */
inline static void teavpn_server_tcp_tun_handle(server_tcp_mstate *__restrict__ mstate)
{
  uint16_t error_count = 0;
  char srv_pkt_arena[PACKET_ARENA_SIZE];
  server_tcp_mstate *mstate = (server_tcp_mstate *)_mstate;
  teavpn_srv_pkt *srv_pkt = (teavpn_srv_pkt *)srv_pkt_arena;
  register int tun_fd = mstate->tun_fd;
  register ssize_t read_ret;

  srv_pkt->type = SRV_PKT_DATA;

read_from_tun:
  read_ret = read(tun_fd, srv_pkt->data, SERVER_READ_BUFFER);
  M_READ_ERROR_HANDLE(read_ret, {
    error_count++;
    if (error_count >= MAX_ERROR_READ) {
      debug_log(0, "Reached the max number of error read");
      teavpn_server_tcp_stop_all(mstate);
      goto ret;
    }
    goto read_from_tun;
  });

  M_READ_ZERO_HANDLE(read_ret, {
    debug_log(0, "Read returned zero");
    error_count++;
    if (error_count >= MAX_ERROR_READ) {
      debug_log(0, "Reached the max number of error read");
      teavpn_server_tcp_stop_all(mstate);
      goto ret;
    }
    goto read_from_tun;
  });
}

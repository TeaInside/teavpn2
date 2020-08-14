
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <teavpn/server/tcp.h>

inline static bool teavpn_server_tcp_init(server_tcp_state *tcp_state);
inline static bool teavpn_server_tcp_socket_setup(int sock_fd);

/**
 * @param server_state *state
 * @return int
 */
__attribute__((force_align_arg_pointer))
int teavpn_server_tcp_run(server_state *state)
{
  int ret = 0;
  server_tcp_state tcp_state;

  tcp_state.server_state = state;
  tcp_state.stop_all     = false;

  /* Init TCP socket. */
  if (!teavpn_server_tcp_init(&tcp_state)) {
    ret = 1;
    goto close_conn;
  }


close_conn:

  return ret;
}

/** 
 * @param server_tcp_state  *tcp_state
 * @return bool
 */
inline static bool teavpn_server_tcp_init(server_tcp_state *tcp_state)
{
  server_state  *state = tcp_state->server_state;
  server_config *config = state->config;


  /* Create TCP socket (SOCK_STREAM). */
  debug_log(0, "Creating TCP socket...");

  tcp_state->sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (tcp_state->sock_fd < 0) {
    perror("Socket creation failed");
    error_log("Cannot create TCP socket");
    return false;
  }

  debug_log(0, "TCP socket created successfully");


  /**
   * Setup TCP socket.
   */
  debug_log(0, "Setting up socket file descriptor...");
  if (!teavpn_server_tcp_socket_setup(tcp_state->sock_fd)) {
    return false;
  }
  debug_log(0, "Socket file descriptor set up successfully");


  /**
   * Prepare server bind address data.
   */
  bzero(&(tcp_state->server_addr), sizeof(struct sockaddr_in));
  tcp_state->server_addr.sin_family = AF_INET;
  tcp_state->server_addr.sin_port = htons(config->bind_port);
  tcp_state->server_addr.sin_addr.s_addr = inet_addr(config->bind_addr);


  /**
   * Bind socket to address.
   */
  if (
      bind(
        tcp_state->sock_fd,
        (struct sockaddr *)&(tcp_state->server_addr),
        sizeof(tcp_state->server_addr)
      ) < 0
    ) {
    perror("Bind failed");
    error_log("Bind socket failed");
    return false;
  }


  /**
   * Listen socket.
   */
  if (listen(tcp_state->sock_fd, config->backlog) < 0) {
    perror("Listen failed");
    error_log("Listen socket failed");
    return false;
  }


  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);

  debug_log(0, "Listening on %s:%d...", config->bind_addr, config->bind_port);

  return true;
}


/**
 * @param int sock_fd
 * @return bool
 */
inline static bool teavpn_server_tcp_socket_setup(int sock_fd)
{
  int opt_1 = 1;

  #define SET_SOCK_OPT(LEVEL, OPTNAME, OPTVAL, OPTLEN) \
    if (setsockopt(sock_fd, LEVEL, OPTNAME, OPTVAL, OPTLEN) < 0) { \
      perror("setsockopt()"); \
      error_log("setsockopt() error"); \
      return false; \
    }

  SET_SOCK_OPT(SOL_SOCKET, SO_REUSEADDR, (void *)&opt_1, sizeof(opt_1));
  SET_SOCK_OPT(IPPROTO_TCP, TCP_NODELAY, (void *)&opt_1, sizeof(opt_1));

  return true;

  #undef SET_SOCK_OPT
}

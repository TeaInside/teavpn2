
#ifndef TEAVPN__SERVER__TCP_H
#define TEAVPN__SERVER__TCP_H

#include <teavpn/server/common.h>

typedef struct _server_tcp_state {

  int                   sock_fd;
  int                   pipe_fd[2];
  struct pollfd         *fds;
  nfds_t                nfds;
  int                   timeout;
  bool                  stop_all;


  server_state          *server_state;
  struct sockaddr_in    server_addr;

} server_tcp_state;

#endif

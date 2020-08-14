
#ifndef TEAVPN__SERVER__TCP_H
#define TEAVPN__SERVER__TCP_H

#include <teavpn/server/common.h>

typedef struct _server_tcp_state {

  int                   sock_fd;
  struct sockaddr_in    server_addr;
  struct pollfd         *fds;
  server_state          *server_state;
  bool                  stop_all;

} server_tcp_state;

#endif


#ifndef TEAVPN__SERVER__TCP_H
#define TEAVPN__SERVER__TCP_H

#include <teavpn/server/common.h>

#define RECV_BUF_SIZE  4096
#define IFACE_BUF_SIZE 4096

typedef struct _tcp_channel {
  struct pollfd         *fds;
  uint32_t              seq;
  bool                  used;
  teavpn_auth           auth;

  /* Allocated private IP for virtual network interface. */
  __be32                inet4;
  __be32                inet4_bcmask;

  uint16_t              recvi;
  char                  recv_buf[RECV_BUF_SIZE];
  uint16_t              ifacei;
  char                  iface_buf[IFACE_BUF_SIZE];
} tcp_channel;

typedef struct _server_tcp_state {

  int                   sock_fd;
  int                   pipe_fd[2];
  struct pollfd         *fds;
  nfds_t                nfds;
  int                   timeout;
  bool                  stop_all;

  tcp_channel           *channels;
  uint16_t              conn_num;        /* Number of connected clients. */
  uint16_t              online_chan;     /* Number of connected and authenticated clients. */
  int32_t               free_chan_index; /* Must be -1 if the channel array is full. */

  server_state          *server_state;
  struct sockaddr_in    server_addr;

} server_tcp_state;

#endif

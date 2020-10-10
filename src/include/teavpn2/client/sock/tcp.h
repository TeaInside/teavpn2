
#ifndef TEAVPN2__CLIENT__SOCK__COMMON_H
#define TEAVPN2__CLIENT__SOCK__COMMON_H

#include <teavpn2/global/packet.h>

typedef struct _client_tcp_state {
  bool                  is_authorized;

  int                   net_fd;         /* Master socket fd. */
  int                   tun_fd;         /* TUN/TAP fd.       */

  bool                  stop;           /* Stop signal.      */
  client_cfg            *config;        /* Server config.    */

  char                  recv_buff[];
  size_t                recv_size;
  char                  send_buff[];
  size_t                send_size;
} client_tcp_state;

#endif

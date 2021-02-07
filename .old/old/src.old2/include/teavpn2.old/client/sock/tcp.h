
#ifndef TEAVPN2__CLIENT__SOCK__COMMON_H
#define TEAVPN2__CLIENT__SOCK__COMMON_H

#if defined(__linux__)
#  include <linux/if.h>
#  include <linux/if_tun.h>
#  include <arpa/inet.h>
#else
#  error "Compiler is not supported!"
#endif

#include <teavpn2/global/types.h>

#define I4CHRZ (sizeof("xxx.xxx.xxx.xxx"))

/* Recv buffer size. */
#define RECVBZ (6144)

/* Send buffer size. */
#define SENDBZ (6144)

typedef struct _client_tcp_state {
  bool                  is_authorized;

  int                   net_fd;             /* Master socket fd.     */
  int                   tun_fd;             /* TUN/TAP fd.           */

  bool                  stop;               /* Stop signal.          */
  client_cfg            *config;            /* Server config.        */

  int                   pipe_fd[2];         /* Pipe fd.              */

  char                  recv_buff[RECVBZ];  
  size_t                recv_size;
  uint64_t              recv_count;         /* Number of recv calls. */

  char                  send_buff[SENDBZ];
  size_t                send_size;
  uint64_t              send_count;         /* Number of send calls. */
} client_tcp_state;

int
tvpn_client_tcp_run(client_cfg *config);

#endif


#ifndef TEAVPN2__SERVER__SOCK__TCP_H
#define TEAVPN2__SERVER__SOCK__TCP_H

#if defined(__linux__)
#  include <linux/if.h>
#  include <linux/if_tun.h>
#  include <arpa/inet.h>
#  include <pthread.h>
#else
#  error "Compiler is not supported!"
#endif

#include <teavpn2/global/types.h>

#define TCP_BUFFER_SIZE (6144)

typedef struct _tcp_channel {
  bool                stop;
  bool                is_used;
  bool                is_connected;
  bool                is_authorized;

#if defined(__linux__)
  int                 tun_fd;        /* TUN/TAP queue fd.                */
#endif
  int                 cli_fd;        /* FD that comunicates with client. */

#if defined(__linux__)
  pthread_t           thread;
  pthread_mutex_t     ht_mutex;
#endif

  __be32              p_ipv4;
  __be32              p_ipv4_netmask;

  char                *username[255];
  char                r_ip_src[IPV4_LEN]; /* Human-readable remote IPv4.  */
  uint16_t            r_port_src;         /* Host byte order remote port. */

#if defined(__linux__)
  struct sockaddr_in  addr;
#endif

  char                recv_buff[TCP_BUFFER_SIZE];
  size_t              recv_size;
  uint64_t            recv_c;             /* Recv count.  */
  uint8_t             recv_err_c;         /* Error count. */

  char                send_buff[TCP_BUFFER_SIZE];
  size_t              send_size;
  uint64_t            send_c;             /* Send count.  */
  uint8_t             send_err_c;         /* Error count. */
} tcp_channel;


typedef struct _server_tcp_state {
  int                   net_fd;         /* Master socket fd.        */
  bool                  stop;           /* Stop signal.             */
  server_cfg            *config;        /* Server config.           */
  tcp_channel           *channels;      /* Client channels.         */

#if defined(__linux__)
  int                   pipe_fd[2];     /* Pipe for poll interrupt. */
#endif

} server_tcp_state;


int
tvpn_server_tcp_run(server_cfg *config);

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP_H */


#ifndef TEAVPN2__SERVER__SOCK__TCP_H
#define TEAVPN2__SERVER__SOCK__TCP_H

#if defined(__linux__)
#  include <linux/if.h>
#  include <linux/if_tun.h>
#else

#  error "Compiler is not supported!"

typedef unsigned int __be32;

#endif

typedef struct _tcp_channel {
  bool                  is_used;
  bool                  is_connected;
  bool                  authorized;

  int                   tun_fd;
  int                   cli_fd;

  uint64_t              recv_count;
  uint64_t              send_count;

  pthread_t             thread;
  pthread_mutex_t       ht_mutex;

  __be32                ipv4;
  __be32                ipv4_netmask;

  char                  *username;

  char                  r_ip_src[sizeof("xxx.xxx.xxx.xxx")];
  uint16_t              r_port_src;
  struct sockaddr_in    addr;

  char                  recv_buff[sizeof(client_pkt) + 1024];
  size_t                recv_size;
  char                  send_buff[sizeof(server_pkt) + 1024];
  size_t                send_size;
} tcp_channel;


typedef struct _server_tcp_state {
  int                   net_fd;         /* Master socket fd. */
  bool                  stop;           /* Stop signal.      */
  server_cfg            *config;        /* Server config.    */
  tcp_channel           *channels;      /* Client channels.  */
} server_tcp_state;


bool
tvpn_auth_tcp(auth_pkt *auth_p, tcp_channel *chan,
              client_auth_tmp *auth_tmp);

#endif

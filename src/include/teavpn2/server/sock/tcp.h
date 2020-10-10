
#ifndef TEAVPN2__SERVER__SOCK__TCP_H
#define TEAVPN2__SERVER__SOCK__TCP_H

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

#define HP_CC(chan) (chan)->r_ip_src, (chan)->r_port_src

typedef struct _tcp_channel {
  bool                  is_used;
  bool                  is_connected;
  bool                  is_authorized;

  int                   tun_fd;            /* TUN/TAP queue fd. */
  int                   cli_fd;            /* Client TCP fd.    */

  pthread_t             thread;
  pthread_mutex_t       ht_mutex;

  __be32                p_ipv4;
  __be32                p_ipv4_netmask;

  char                  *username;

  char                  r_ip_src[I4CHRZ];  /* Human-readable remote IPv4.  */
  uint16_t              r_port_src;        /* Host byte order remote port. */
  struct sockaddr_in    addr;

  char                  recv_buff[RECVBZ];
  size_t                recv_size;         
  uint64_t              recv_count;        /* Number of recv calls.        */

  char                  send_buff[SENDBZ]; /* send_buff size to be sent.   */
  size_t                send_size;
  uint64_t              send_count;        /* Number of send calls.        */
} tcp_channel;


typedef struct _server_tcp_state {
  int                   net_fd;         /* Master socket fd.      */
  bool                  stop;           /* Stop signal.           */
  server_cfg            *config;        /* Server config.         */
  tcp_channel           *channels;      /* Client channels.       */
  int                   pipe_fd[2];     /* Pipe fd for interrupt. */
} server_tcp_state;


int
tvpn_server_tcp_run(server_cfg *state);

#endif

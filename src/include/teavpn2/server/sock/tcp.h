
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

#define MAX_RECV_ERR_CC (10)

typedef struct _tcp_channel {
  bool                  stop;
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
  uint8_t               recv_err_c;

  char                  send_buff[SENDBZ]; /* send_buff size to be sent.   */
  size_t                send_size;
  uint64_t              send_count;        /* Number of send calls.        */
  uint8_t               send_err_c;
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

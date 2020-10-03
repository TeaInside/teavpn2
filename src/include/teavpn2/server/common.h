
#ifndef TEAVPN2__SERVER__COMMON_H
#define TEAVPN2__SERVER__COMMON_H

#include <linux/types.h>
#include <teavpn2/global/common.h>

typedef struct _server_iface_cfg {

  char                  *dev;           /* Interface name. */

  char                  *ipv4;          /* IPv4. */
  char                  *ipv4_bcmask;   /* IPv4 broadcast mask. */
  uint16_t              mtu;            /* MTU. */

#if 0
  char                  *ipv6;          /* IPv6. */
  char                  *ipv6_bcmask;   /* IPv6 broadcast mask. */
#endif

} server_iface_cfg;



typedef struct _server_socket_cfg {
  char                  *bind_addr;     /* Socket server bind address. */
  int                   backlog;        /* Socket listen backlog. */
  uint16_t              bind_port;      /* Socket server bind port. */
  socket_type           type;           /* Socket type, TCP/UDP. */
} server_socket_cfg;


typedef struct _server_cfg {

  char                  *config_file;   /* Config file. */
  char                  *data_dir;      /* Data directory. */
  server_iface_cfg      iface;          /* Virtual interface configuration. */
  server_socket_cfg     sock;           /* Socket configuration. */

} server_cfg;


typedef struct _tcp_channel {
  bool                  is_used;
  bool                  authorized;
  int                   tun_fd;
  int                   cli_fd;
  uint64_t              recv_count;
  uint64_t              send_count;

  __be32                ipv4;
  char                  *username;
} tcp_channel;

typedef struct _tcp_state {
  int                   *tun_fds;       /* TUN/TAP fd. */
  int                   sock_fd;        /* Master socket fd. */

  server_cfg            *config;        /* Server config. */
  tcp_channel           *channels;
} tcp_state;

/* argv_parser */
bool tvpn_server_argv_parse(
  int argc,
  char *argv[],
  char *envp[],
  server_cfg *config
);
/* End of argv_parser */


/* config */
bool tvpn_server_load_config_file(char *file, server_cfg *config);
/* End of config */

int tvpn_server_run(server_cfg *config);

int tvpn_server_tcp_run(server_cfg *state);

/* iface */
int tun_alloc(char *dev, int flags);
int tun_set_queue(int fd, int enable);
/* End of iface */

#endif

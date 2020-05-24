
#ifndef TEAVPN__SERVER__TCP_H
#define TEAVPN__SERVER__TCP_H

#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <teavpn2/server/socket.h>
#include <teavpn2/global/data_struct.h>

typedef struct _server_tcp_mstate server_tcp_mstate;

typedef struct {
  bool stop;
  bool is_online;
  bool is_authenticated;

  int fd;

  /* Client address info. */
  struct sockaddr_in saddr;
  char saddr_r[32]; /* Readable source address. */
  uint8_t saddr_r_len;
  uint16_t sport_r; /* Readable source port. */

  /* Client error info. */
  uint16_t error_recv_count;
  uint16_t error_send_count;

  /* Write bytes info. */
  ssize_t recv_ret;
  ssize_t read_ret;

  uint32_t priv_ip;

  /* Thread that serves the client. */
  pthread_t thread;
  server_tcp_mstate *mstate;

  /* Packet pointer. */
  teavpn_cli_pkt *cli_pkt;
  teavpn_srv_pkt *srv_pkt;
} tcp_channel;

struct _server_tcp_mstate {
  /* File descriptors. */
  int net_fd;
  int tun_fd;
  int pipe_fd[2];

  /* Interface info and config. */
  iface_info *iinfo;
  teavpn_server_config *config;

  /* Server addr for socket init. */
  struct sockaddr_in server_addr;

  /* Pointer to channels (array). */
  tcp_channel *channels;

  /* Free channel index. */
  int16_t fci;

  /* Stop signal. */
  bool stop_all;

  /* Pointer to fds array (for poll). */
  struct pollfd *fds;

  /* Server tunnel address in __be32 */
  __be32 s_ip;
};

int teavpn_server_tcp_run(iface_info *iinfo, teavpn_server_config *_config);

#endif

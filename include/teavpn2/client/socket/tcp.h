
#ifndef TEAVPN__CLIENT__SOCKET__TCP_H
#define TEAVPN__CLIENT__SOCKET__TCP_H

#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <teavpn2/client/socket.h>
#include <teavpn2/global/data_struct.h>
#include <teavpn2/client/socket.h>

typedef struct _client_tcp_mstate client_tcp_mstate;

struct _client_tcp_mstate {
  int net_fd;
  int tun_fd;
  int pipe_fd[2];
  iface_info *iinfo;
  teavpn_client_config *config;
  struct sockaddr_in server_addr;
  pthread_t iface_reader;
  pthread_t recv_worker;
  bool stop_all;
};

int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *_config);

#endif


#ifndef TEAVPN__SERVER__TCP_H
#define TEAVPN__SERVER__TCP_H

#include <pthread.h>
#include <teavpn/server/common.h>

#define RECV_BUF_SIZE 
#define READ_BUF_SIZE

/*
 * Struct for every single connection.
 */
typedef struct _tcp_conn {

  int                 cli_fd;   /* fd to read/write from/to client. */
  int                 tun_fd;   /* tun_fd queue used by this client. */

  /* recv from cli_fd. */
  uint16_t            recvi;         
  char                recv_buf[RECV_BUF_SIZE]; 

  /* read from tun_fd. */
  uint16_t            readi;
  char                read_buf[READ_BUF_SIZE];
} tcp_conn;


typedef struct _tcp_server_state {

  int                   net_fd;        /* Main socket file descriptor. */
  int                   pipe_fd[2];    /* Pipe fd to interrupt main event loop. */

  struct pollfd         *fds;          /* Poll fds. */
  nfds_t                nfds;          /* Number of fds. */

  tcp_conn              *conn;         /* Connection entries. */
  uint16_t              conn_num;      /* Number of active connections. */
  uint16_t              online_num;    /* Number of authenticated connections. */
  int32_t               fci;           /* Current usable array index. */

  server_state          *srv_state;    /* Server state. */
} tcp_server_state;

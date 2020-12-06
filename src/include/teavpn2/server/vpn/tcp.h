
#ifndef TEAVPN2__SERVER__TEAVPN2__TCP_H
#define TEAVPN2__SERVER__TEAVPN2__TCP_H

typedef struct _tcp_state
{
  int       net_fd;
  int       pipe_fd[2];
  srv_cfg   *cfg;

} tcp_state;

#endif /* #ifndef TEAVPN2__SERVER__TEAVPN2__TCP_H */

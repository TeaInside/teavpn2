
#ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#define SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "linux/init.h"
#include "linux/clean_up.h"

/**
 * @param srv_cfg *cfg
 * @return int
 */
inline static int
tsrv_run_tcp(srv_cfg *cfg)
{
  int            retval   = 1;
  const uint16_t max_conn = cfg->sock.max_conn;


  tcp_state      state    = {
    .net_fd  = -1,
    .pipe_fd = {-1, -1},
    .cfg     = cfg,
    .chan    = NULL,
    .stop    = false
  };

  state.chan = (tcp_channel *)malloc(sizeof(tcp_channel) * max_conn);
  tsrv_init_channel_tcp(state.chan, max_conn);

  /*
   * [Note]
   * `state.chan` array must be allocated first since
   * `tsrv_init_tun_fd` will fill the channels with
   * tun_fd queue.
   */
  if (!tsrv_init_tun_fd_tcp(&state)) {
    goto ret;
  }

  if (!tsrv_init_sock_tcp(&state)) {
    goto ret;
  }

  if (!tsrv_init_pipe_tcp(&state)) {
    goto ret;
  }



  retval = 0;
ret:
  tsrv_clean_up_tcp(&state);
  return retval;
}


#endif /* #ifndef SRC_TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H */

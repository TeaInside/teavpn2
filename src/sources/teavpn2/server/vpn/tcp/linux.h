
#ifndef TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H
#define TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H

#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <teavpn2/server/vpn/tcp.h>

#include "sock/linux.h"
#include "clean_up/linux.h"

/**
 * @param srv_cfg *cfg
 * @return int
 */
inline static int
tsrv_run_tcp(srv_cfg *cfg)
{
  int       retval = 1;
  tcp_state state  = {
    .net_fd  = -1,
    .pipe_fd = {-1, -1},
    .cfg     = cfg,
  };


  if (!tsrv_init_sock_tcp(&state)) {
    goto ret;
  }

  if (!tsrv_init_pipe(&state)) {
    goto ret;
  }

  if (!tsrv_init_tun_fd(&state)) {
    
  }

ret:
  tsrv_clean_up_tcp(&state);
  return retval;
}


#endif /* #ifndef TEAVPN2__SERVER__TEAVPN2__TCP__LINUX_H */

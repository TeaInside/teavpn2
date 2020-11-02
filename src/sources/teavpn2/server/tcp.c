
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <teavpn2/server/common.h>
#include <teavpn2/server/tcp.h>

srv_tcp *g_srv;

#include "platform/tcp_init.h"
#include "platform/tcp_clean_up.h"

/**
 * @param srv_cfg *cfg
 * @return int
 */
int
tvpn_srv_tcp_run(srv_cfg *cfg)
{
  int     ret;
  srv_tcp srv;

  g_srv = &srv;

  if (unlikely(!tvpn_srv_tcp_init(&srv, cfg))) {
    ret = 1;
    goto ret;
  }








  ret = 0;
ret:
  tvpn_srv_tcp_clean_up(&srv);
  return ret;
}

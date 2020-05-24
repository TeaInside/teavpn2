
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <linux/ip.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <teavpn2/global/iface.h>
#include <teavpn2/global/data_struct.h>
#include <teavpn2/client/common.h>
#include <teavpn2/client/socket/tcp.h>



/**
 * @param teavpn_client_config *config
 * @return bool
 */
__attribute__((force_align_arg_pointer))
int teavpn_client_tcp_run(iface_info *iinfo, teavpn_client_config *config)
{
  int ret = 0;
  client_tcp_mstate mstate;

  /* Initialize mstate values. */
  bzero(&mstate, sizeof(client_tcp_mstate));
  mstate.iinfo = iinfo;
  mstate.config = config;
  mstate.tun_fd = iinfo->tun_fd;
  config->mstate = (void *)&mstate;
}

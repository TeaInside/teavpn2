
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/if.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/if_tun.h>

#include <teavpn2/client/common.h>

/**
 * @param server_cfg *config
 * @return int
 */
__attribute__((force_align_arg_pointer))
int tvpn_client_tcp_run(client_cfg *config)
{
  int ret = 1;





  ret:

  return ret;
}

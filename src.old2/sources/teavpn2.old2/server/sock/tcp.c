
#include <string.h>
#include <teavpn2/server/common.h>

#define TAKE_INLINE_ABSTRACTIONS
#include <teavpn2/server/sock/tcp.h>
#undef TAKE_INLINE_ABSTRACTIONS

#if defined(__linux__)
#  include <errno.h>
#  include <unistd.h>
#  include <netinet/tcp.h>
#  include "tcp/linux.h"
#else
#  error Compiler is not supported!
#endif

/**
 * @param const char  *bind_addr
 * @param uint16_t    bind_port
 * @param int         backlog
 * @return int
 */
int
srv_init_tcp4(const char *bind_addr, uint16_t bind_port, int backlog)
{
  return ins_srv_init_tcp4(bind_addr, bind_port, backlog);
}


/**
 * @param int          sock_fd
 * @param srv_sock_cfg *cfg
 * @return bool
 */
bool
srv_set_tcp4(int sockfd, srv_sock_cfg *sock)
{
  return ins_srv_set_tcp4(sockfd, sock);
}

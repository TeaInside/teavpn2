

#if defined(__linux__)
#  include "tcp/linux.h"
#else
#  error Compiler is not supported!
#endif



/**
 * @param srv_cfg *cfg
 * @return int
 */
static int
tsrv_tcp_run(srv_cfg *cfg)
{
  int             sockfd;
  int             tunfd;
  srv_iface_cfg   *iface     = &(cfg->iface);
  srv_sock_cfg    *sk        = &(cfg->sock);

  

  sockfd = srv_init_tcp4(sk->bind_addr, sk->bind_port, sk->backlog);

  if (unlikely(sockfd < 0)) {
    goto err;
  }


  if (unlikely(!srv_set_tcp4(sockfd, sk))) {
    goto err;
  }


  tunfd = srv_iface_init(iface);

  if (unlikely(tunfd < 0)) {
    goto err;
  }


  return 0;

err:
  return 1;
}

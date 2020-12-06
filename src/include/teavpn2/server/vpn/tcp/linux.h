
#ifndef TEAVPN2__SERVER__VPN__TCP__LINUX_H
#define TEAVPN2__SERVER__VPN__TCP__LINUX_H

#include <pthread.h>
#include <teavpn2/server/common.h>

#define RECV_SIZ (4096u)
#define SEND_SIZ (4096u)

typedef struct _tcp_channel
{
  bool                stop;
  bool                is_used;
  bool                is_connected;
  bool                is_authorized;

  int                 tun_fd;             /* FD for writing TUN/TAP queue.     */
  int                 cli_fd;             /* FD for data transfer with client. */

  pthread_t           thread;
  pthread_mutex_t     ht_mutex;

  __be32              p_ipv4;             /* Big endian order IPv4 private. */
  __be32              p_ipv4_netmask;     /* Big endian order IPv4 netmask. */

  char                username[255];
  char                r_ip_src[IPV4L];    /* Human-readable remote IPv4.    */
  uint16_t            r_port_src;         /* Host byte order remote port.   */

  struct sockaddr_in  addr;               /* Remote address and port info.  */

  char                recv_buff[RECV_SIZ];
  size_t              recv_size;
  uint64_t            recv_c;             /* Recv count.  */
  uint8_t             recv_err_c;         /* Error count. */

  char                send_buff[SEND_SIZ];
  size_t              send_size;
  uint64_t            send_c;             /* Send count.  */
  uint8_t             send_err_c;         /* Error count. */
} tcp_channel;


typedef struct _tcp_state
{
  int           net_fd;
  int           pipe_fd[2];
  srv_cfg       *cfg;
  tcp_channel   *chan;
  bool          stop;
} tcp_state;

#endif /* #ifndef TEAVPN2__SERVER__VPN__TCP__LINUX_H */


#ifndef TEAVPN2__SERVER__SOCK__TCP_H
#define TEAVPN2__SERVER__SOCK__TCP_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

/**
 * @param int    sockfd
 * @param void   *buf
 * @param size_t len
 * @param int    flags
 * @return size_t
 */
inline static ssize_t
mrecv(int sockfd, void *buf, size_t len, int flags)
{
  return recv(sockfd, buf, len, flags);
}

/**
 * @param int    sockfd
 * @param void   *buf
 * @param size_t len
 * @param int    flags
 * @return size_t
 */
inline static ssize_t
msend(int sockfd, const void *buf, size_t len, int flags)
{
  return send(sockfd, buf, len, flags);
}

int
srv_init_tcp4(const char *bind_addr, uint16_t bind_port, int backlog);

bool
srv_set_tcp4(int sockfd, srv_sock_cfg *sock);


#ifdef TAKE_INLINE_ABSTRACTIONS

inline static int
ins_srv_init_tcp4(const char *bind_addr, uint16_t bind_port, int backlog);

inline static bool
ins_srv_set_tcp4(int sockfd, srv_sock_cfg *sock);

#endif /* #ifdef TAKE_INLINE_ABSTRACTIONS */


#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP_H */

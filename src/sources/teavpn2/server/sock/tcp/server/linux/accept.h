
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H

/**
 * @param tcp_channel *__restrict__ state
 * @return bool
 */
inline static void
tvpn_server_tcp_accept(server_tcp_state *__restrict__ state)
{
  (void)state;
}

#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__ACCEPT_H */

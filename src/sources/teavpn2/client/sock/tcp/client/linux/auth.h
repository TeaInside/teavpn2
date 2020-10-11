
#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX_H
#  error This file must only be included from   \
         teavpn2/client/sock/tcp/client/linux.h
#endif

#ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H
#define TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H


/**
 * @param  client_tcp_state * __restrict__ state
 * @return bool
 */
inline static bool
tvpn_client_tcp_auth(client_tcp_state * __restrict__ state)
{

  return true;
}

#endif /* #ifndef TEAVPN2__CLIENT__SOCK__TCP__CLIENT__LINUX__AUTH_H */

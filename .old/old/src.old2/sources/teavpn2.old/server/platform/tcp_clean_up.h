
#ifndef SERVER__PLATFORM__TCP_CLEAN_UP_H
#define SERVER__PLATFORM__TCP_CLEAN_UP_H


inline static void
tvpn_srv_tcp_clean_up(srv_tcp *srv);


#if defined(__linux__)
#  include "linux/tcp_clean_up.h"
#else
#  error "Compiler is not supported!"
#endif



#endif /* #ifndef SERVER__PLATFORM__TCP_CLEAN_UP_H */

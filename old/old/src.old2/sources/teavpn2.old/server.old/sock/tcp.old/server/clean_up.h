
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__CLEAN_UP_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__CLEAN_UP_H

inline static void
tvpn_server_tcp_clean_up(server_tcp_state *state);


#if defined(__linux__)
#  include "platform/linux/clean_up.h"
#else
#  error "Compiler is not supported!"
#endif




#endif /* #ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__CLEAN_UP_H */

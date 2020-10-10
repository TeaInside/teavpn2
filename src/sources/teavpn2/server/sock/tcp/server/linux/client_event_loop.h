
#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX_H
#  error This file must only be included from   \
         teavpn2/server/sock/tcp/server/linux.h
#endif

#ifndef TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H
#define TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H

inline static void *
tvpn_server_tcp_thread_worker(void *__restrict__ _chan)
{
  tcp_channel *chan = (tcp_channel *)_chan;


  debug_log(0, "[%s:%d] Spawning a thread to handle new connection",
            HP_CC(chan));

  return NULL; 
}

#endif /* #ifndef
TEAVPN2__SERVER__SOCK__TCP__SERVER__LINUX__CLIENT_EVENT_LOOP_H */

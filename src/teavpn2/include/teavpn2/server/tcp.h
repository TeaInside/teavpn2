
#ifndef TEAVPN2__SERVER__TCP_H
#define TEAVPN2__SERVER__TCP_H

#include <teavpn2/base.h>
#include <teavpn2/server/common.h>


int teavpn_server_tcp(struct srv_cfg *cfg);
int teavpn_server_tcp_handler(struct srv_cfg *cfg);

#endif /* #ifndef TEAVPN2__SERVER__TCP_H */

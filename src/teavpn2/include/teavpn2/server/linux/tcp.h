
#ifndef __TEAVPN2__SERVER__LINUX__TCP_H
#define __TEAVPN2__SERVER__LINUX__TCP_H

#include <poll.h>
#include <arpa/inet.h>
#include <teavpn2/server/common.h>
#include <teavpn2/client/linux/tcp.h>
#include <teavpn2/server/linux/tcp_packet.h>
#include <teavpn2/client/linux/tcp_packet.h>


int teavpn_server_tcp_handler(struct srv_cfg *cfg);

#endif /* #ifndef __TEAVPN2__SERVER__LINUX__TCP_H */

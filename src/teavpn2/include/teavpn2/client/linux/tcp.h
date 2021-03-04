
#ifndef __TEAVPN2__CLIENT__LINUX__TCP_H
#define __TEAVPN2__CLIENT__LINUX__TCP_H

#include <stdint.h>
#include <teavpn2/client/common.h>
#include <teavpn2/server/linux/tcp_packet.h>
#include <teavpn2/client/linux/tcp_packet.h>


int teavpn_client_tcp_handler(struct cli_cfg *cfg);

#endif /* #ifndef __TEAVPN2__CLIENT__LINUX__TCP_H */

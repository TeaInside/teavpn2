

#ifndef TEAVPN2__NET__TCP_PKT_H
#define TEAVPN2__NET__TCP_PKT_H

#define TEAVPN2__NET__TCP_PKT_H__INCLUDE
#include <teavpn2/net/tcp_pkt_client.h>
#include <teavpn2/net/tcp_pkt_server.h>
#undef TEAVPN2__NET__TCP_PKT_H__INCLUDE

static_assert(sizeof(tsrv_pkt_t) == (
	         1     /* type   */
	       + 1     /* npad   */
	       + 2     /* length */
	       + 4096  /* data   */
	      ), "Bad sizeof(tsrv_pkt_t)");
static_assert(sizeof(tcli_pkt_t) == (
	         1     /* type   */
	       + 1     /* npad   */
	       + 2     /* length */
	       + 4096  /* data   */
	      ), "Bad sizeof(tcli_pkt_t)");

static_assert(offsetof(tsrv_pkt_t, type) == 0, "Bad offsetof(tsrv_pkt_t, type)");
static_assert(offsetof(tcli_pkt_t, type) == 0,
	      "Bad offsetof(tcli_pkt_t, type)");

static_assert(offsetof(tsrv_pkt_t, npad) == 1, "Bad offsetof(tsrv_pkt_t, npad)");
static_assert(offsetof(tcli_pkt_t, npad) == 1,
	      "Bad offsetof(tcli_pkt_t, npad)");

static_assert(offsetof(tsrv_pkt_t, length) == 2,
	      "Bad offsetof(tsrv_pkt_t, length)");
static_assert(offsetof(tcli_pkt_t, length) == 2,
	      "Bad offsetof(tcli_pkt_t, length)");

static_assert(offsetof(tsrv_pkt_t, raw_data) == 4,
	      "Bad offsetof(tsrv_pkt_t, raw_data)");
static_assert(offsetof(tcli_pkt_t, raw_data) == 4,
	      "Bad offsetof(tcli_pkt_t, raw_data)");

#endif /* #ifndef TEAVPN2__NET__TCP_PKT_H */

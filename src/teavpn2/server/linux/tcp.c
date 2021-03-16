
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/cpu.h>
#include <teavpn2/base.h>
#include <teavpn2/auth.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/tcp.h>
#include <teavpn2/net/tcp_pkt.h>


#define CLIENT_MAX_ERROR	(0x0fu)
#define SERVER_MAX_ERROR	(0x0fu)
#define EPOLL_CLIENT_MAP_SIZE	(0xffffu)
#define EPOLL_INPUT_EVENTS	(EPOLLIN | EPOLLPRI)

#define IP_MAP_SHIFT		(0x00001u)	/* Preserve map to nop */
#define IP_MAP_TO_NOP		(0x00000u)	/* Unused map slot     */

/* Macros for printing  */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


struct client_slot {
	bool			is_auth;
	bool			is_used;
	bool			is_conn;
	uint8_t			err_c;

	/* Client file descriptor */
	int			cli_fd;

	/* Send counter */
	uint32_t		send_c;

	/* Recv counter */
	uint32_t		recv_c;

	/*
	 * To find the index in client slots which
	 * refer to its client instance.
	 *
	 *   state->clients[slot_index]
	 *
	 */
	uint16_t		slot_index;

	/* Remote address and port */
	uint16_t		src_port;
	char			src_ip[IPV4_L];

	/* Client username */
	char			uname[64];

	uint32_t		private_ip;
	size_t			recv_s;
	utcli_pkt_t		recv_buf;
};


struct srv_tcp_state {
	bool			stop_event_loop;
	bool			need_iface_down;
	bool			set_affinity_ok;
	bool			err_c;

	/* File descriptors */
	int			epoll_fd;
	int			tcp_fd;
	int			tun_fd;

	struct srv_cfg		*cfg;

	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`.
	 *
	 * The value of ip_map[i][j] is an index of `clients`
	 * slot in this struct. So you can access it like this:
	 * ```c
	 *    struct client_slot *client;
	 *    uint16_t map_to = ip_map[i][j];
	 *
	 *    if (map_to != IP_MAP_TO_NOP) {
	 *        client = &state->clients[map_to - IP_MAP_SHIFT];
	 *
	 *        // use client->xxxx here
	 *
	 *    } else {
	 *        // map is not mapped to client slot
	 *    }
	 * ```
	 */
	uint16_t		(*ip_map)[256];
	struct client_slot	*clients;


	/* How many calls read(tun_fd, buf, size)? */
	uint32_t		read_tun_c;

	/* How many calls write(tun_fd, buf, size)? */
	uint32_t		write_tun_c;

	/* How many bytes has been read() from tun_fd */
	uint64_t		up_bytes;

	/* How many bytes has been write()'en to tun_fd */
	uint64_t		down_bytes;

	cpu_set_t		affinity;
	utsrv_pkt_t		send_buf;
};


static struct srv_tcp_state *g_state;



int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval = 0;
	struct srv_tcp_state state;

	state.cfg = cfg;
	g_state = &state;

	goto out;
out:
	return retval;
}

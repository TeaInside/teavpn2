
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/server/tcp.h>
#include <teavpn2/net/tcp_pkt.h>

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wunused-macros"
#endif

#define MAX_ERR_C	(0xfu)

#define EPL_MAP_SIZE	(0xffffu)

#define EPL_MAP_TO_NOP	(0x0u)
#define EPL_MAP_TO_TUN	(0x1u)
#define EPL_MAP_TO_NET	(0x2u)

/* `EPL_MAP_ADD` must be the number of `EPL_MAP_TO_*` */
#define EPL_MAP_ADD	(0x3u)

#define EPL_IN_EVT	(EPOLLIN | EPOLLPRI)

#define IP_MAP_TO_NOP	(0x0u)
#define IP_MAP_ADD	(0x1u)

/* Macros for printing */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


typedef enum _evt_cli_goto_t {
	RETURN_OK	= 0,
	OUT_CONN_ERR	= 1,
	OUT_CONN_CLOSE	= 2,
} evt_cli_goto_t;


struct client_slot {
	int			cli_fd;

	uint32_t		recv_c;
	uint32_t		send_c;

	uint16_t		client_idx;
	char			uname[64];

	bool			is_auth;
	bool			is_used;
	bool			is_conn;

	uint8_t			err_c;
	char			src_ip[IPV4_L];
	uint16_t		src_port;
	struct_pad(0, 4);

	/* Number of unprocessed bytes in recv_buf */
	size_t			recv_s;

	utcli_pkt_t		recv_buf;
};


/*
 * Stack to retrieve client slot in O(1) time complexity
 */
struct cl_slot_stk {
	uint16_t		sp;	/* Stack pointer       */
	uint16_t		max_sp;	/* Max stack pointer   */
	struct_pad(0, 4);
	uint16_t		*arr;	/* The array container */
};


/*
 * Broadcast array.
 *
 * Whenever there is a packet that should be broadcasted
 * to all clients, we use this struct to enumerate the
 * client index slot.
 */
struct _bc_arr {
	
	uint16_t		n;
	struct_pad(0, 6);
	uint16_t		*arr;
};


struct srv_tcp_state {
	int			epoll_fd;

	int			tcp_fd;
	int			tun_fd;

	struct cl_slot_stk	client_stack;

	struct client_slot	*clients;
	uint16_t		*epoll_map;

	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`
	 */
	uint16_t		(*ip_map)[256];

	struct srv_cfg		*cfg;

	/* Counters */
	uint32_t		read_tun_c;
	uint32_t		write_tun_c;

	struct _bc_arr		bc_idx_arr;

	bool			stop;
};

static int init_state(struct srv_tcp_state *state)
{
	uint16_t *epoll_map = NULL;
	uint16_t (*ip_map)[256] = NULL;
	struct client_slot *clients = NULL;


	init_client_stack();

	init_broadcast_arr();
}



static struct srv_tcp_state *g_state;


static void handle_interrupt(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int32_t push_client_stack(struct _cl_stk *client_stack, uint16_t val)
{
	uint16_t sp = client_stack->sp;

	TASSERT(sp > 0);
	client_stack->arr[--sp] = val;
	client_stack->sp = sp;
	return (int32_t)val;
}


static int32_t pop_client_stack(struct _cl_stk *client_stack)
{
	int32_t val;
	uint16_t sp = client_stack->sp;
	uint16_t max_sp = client_stack->max_sp;

	/* sp must never be higher than max_sp */
	TASSERT(sp <= max_sp);

	if (unlikely(sp == max_sp)) {
		/* There is nothing on the stack */
		return -1;
	}

	val = (int32_t)client_stack->arr[sp];
	client_stack->sp = ++sp;
	return val;
}


/*
 * Caller is responsible to keep track the index (client_idx).
 */
static void reset_client_slot(struct tcp_client *client, uint16_t client_idx)
{
	client->cli_fd      = -1;

	client->recv_c      = 0;
	client->send_c      = 0;

	client->client_idx  = client_idx;

	client->uname[0]    = '_';
	client->uname[1]    = '\0';

	client->is_used     = false;
	client->is_auth     = false;
	client->is_conn     = false;

	client->err_c       = 0;
	client->recv_s      = 0;
}




int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, handle_interrupt);
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGQUIT, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_epoll(&state);
	if (unlikely(retval < 0))
		goto out;
	prl_notice(0, "Initialization Sequence Completed");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}


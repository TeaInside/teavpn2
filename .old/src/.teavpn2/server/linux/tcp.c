
#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/server/linux/tcp.h>
#include <teavpn2/server/linux/iface.h>

#define MAX_ERR_COUNT (15u)
static struct srv_tcp_state *state_g = NULL;

/**
 * -- Connection flow after server initialization sequence completed --
 * 1. Client *connects* to the server.
 * 2. Server *accepts* the connection.
 * 3. Server *sends* welcome banner to client (include version info).
 * 4. Client *sends* auth data to server (username and password).
 * 5. If username and password are wrong, then close connection, else
 *    goto 6.
 * 6. Server *sends* IP configuration to client.
 * 7. Client *sends* configuration acknowledgement.
 * 8. Connection authorized!
 *
 */

static struct srv_tcp_state *g_state; /* For interrupt handler */


static void intr_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	g_state->stop = true;
	(void)sig;
}


static int32_t push_clstack(struct srv_tcp_clstack *stack, uint16_t val)
{
	uint16_t sp = stack->sp;

	assert(sp > 0);
	stack->slot[--sp] = val;
	stack->sp = sp;
	return (int32_t)val;
}


static int32_t pop_clstack(struct srv_tcp_clstack *stack)
{
	int32_t ret;
	uint16_t sp = stack->sp;

	/* sp must never be higher than max_sp */
	assert(sp <= stack->max_sp);

	if (sp == stack->max_sp)
		return -1; /* There is nothing on the stack */

	ret = (int32_t)stack->slot[sp];
	stack->sp = ++sp;
	return ret;
}


static void init_client_slots(struct tcp_client *clients, uint16_t i)
{
	while (i--) {
		memset(&clients[i], 0, sizeof(struct tcp_client));
		clients[i].tun_fd = -1;
		clients[i].cli_fd = -1;
		clients[i].arr_idx = i;
	}
}


static int init_state(struct srv_tcp_state *state)
{
	struct srv_cfg *cfg = state->cfg;
	struct tcp_client *clients = NULL;
	struct srv_tcp_clstack *stack = &state->stack;	
	uint16_t max_conn = cfg->sock.max_conn;
	uint16_t *stack_slot = NULL;


	clients = calloc(max_conn, sizeof(struct tcp_client));
	if (clients == NULL) {
		pr_error("calloc: Cannot allocate memory: %s", strerror(errno));
		return -ENOMEM;
	}

	stack_slot = calloc(max_conn, sizeof(uint16_t));
	if (stack_slot == NULL) {
		free(clients);
		pr_error("calloc: Cannot allocate memory: %s", strerror(errno));
		return -ENOMEM;	
	}

	stack->sp = max_conn;
	stack->max_sp = max_conn;
	stack->slot = stack_slot;

	init_client_slots(clients, max_conn);

	while (max_conn--)
		push_clstack(stack, max_conn);

	state->stop = false;
	state->net_fd = -1;
	state->nfds = 0;
	state->fds = NULL;
	state->n_online = 0;
	state->clients = clients;

	return 0;
}


static void destroy_state(struct srv_tcp_state *state)
{
	free(state->stack.slot);
	free(state->clients);
}


int teavpn_tcp_server(struct srv_cfg *cfg)
{
	int retval = 0;
	struct srv_tcp_state state;

	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;

	signal(SIGINT, intr_handler);
	signal(SIGHUP, intr_handler);
	signal(SIGTERM, intr_handler);
	signal(SIGQUIT, intr_handler);

	retval = init_state(&state);
	if (retval < 0)
		goto out;
	retval = teavpn_tcp_init_iface(&state);
	if (retval < 0)
		goto out;

out:
	destroy_state(&state);
	return retval;
}

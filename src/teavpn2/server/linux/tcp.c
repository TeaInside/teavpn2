
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdalign.h>
#include <teavpn2/base.h>
#include <teavpn2/server/tcp.h>


#define EPT_MAP_SIZE (0xffffu)
#define EPT_MAP_NOP  (0xffffu)
// #define EPT_MAP_PIPE (0x0u)
// #define EPT_MAP_ADD  (0x1u)

struct tcp_client {
	int			cli_fd;		/* Client TCP file descriptor */
	uint32_t		recv_c;		/* sys_recv counter           */
	uint32_t		send_c;		/* sys_send counter           */
	uint16_t		sidx;		/* Client slot index          */
	char			uname[64];
	bool			mt_act;		/* Is mutex need to be freed? */
	bool			is_auth;	/* Is authenticated?          */
	bool			is_used;	/* Is used?                   */
	bool			is_conn;	/* Is connected?              */
	uint8_t			err_c;		/* Error counter              */
	struct_pad(0, 5);
	pthread_mutex_t		mutex;		/* Mutex is mutex             */
};


struct _cl_stk {
	/*
	 * Stack to retrieve client slot in O(1) time complexity
	 */
	uint16_t		sp;		/* Stack pointer       */
	uint16_t		max_sp;		/* Max stack pointer   */
	struct_pad(0, 4);
	uint16_t		*arr;		/* The array container */
};


struct srv_tcp_state {
	int			epm_fd;		/* Epoll fd (main)            */
	int			ept_fd;		/* Epoll fd (thread)          */
	int			net_fd;		/* Main TCP socket fd         */
	int			tun_fd;		/* TUN/TAP fd                 */
	int			piep_fd[2];	/* Pipe fd                    */
	bool			stop;		/* Stop the event loop?       */
	bool			mt_act;		/* Is mutex need to be freed? */
	bool			reconn;		/* Reconnect if conn dropped? */
	uint8_t			reconn_c;	/* Reconnect count            */
	struct_pad(0, 4);
	struct _cl_stk		cl_stk;		/* Stack for slot resolution  */
	uint16_t		*ept_map;	/* Epoll thread map to client */
	struct tcp_client	*(*ipm)[256];	/* IP address map             */
	struct tcp_client	*clients;	/* Client slot                */
	struct srv_cfg		*cfg;		/* Config                     */
	pthread_mutex_t		mutex;		/* Mutex is mutex             */
};


static struct srv_tcp_state *g_state;


static void interrupt_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = 0;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static void tcp_client_init(struct tcp_client *client, uint16_t sidx)
{
	client->cli_fd   = -1;
	client->recv_c   = 0;
	client->send_c   = 0;
	client->uname[0] = '_';
	client->uname[1] = '\0';
	client->sidx     = sidx;
	client->mt_act   = false;
	client->is_used  = false;
	client->is_auth  = false;
	client->is_conn  = false;
	client->err_c    = 0;
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	uint16_t max_conn;
	struct _cl_stk *cl_stk;
	uint16_t *ept_map = NULL;
	uint16_t *stack_arr = NULL;
	struct tcp_client *clients = NULL;
	struct tcp_client *(*ipm)[256] = NULL;

	err = pthread_mutex_init(&state->mutex, NULL);
	if (unlikely(err != 0)) {
		err = (err < 0) ? -err : err;
		pr_err("pthread_mutex_init: " PRERF, PREAR(err));
		return -err;
	}
	state->mt_act = true;

	max_conn = state->cfg->sock.max_conn;

	clients = calloc(max_conn, sizeof(struct tcp_client));
	if (unlikely(clients == NULL))
		goto out_err;

	stack_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(stack_arr == NULL))
		goto out_err;

	ept_map = calloc(EPT_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(ept_map == NULL))
		goto out_err;

	ipm = calloc(256u, sizeof(struct tcp_client *[256u]));
	if (unlikely(ipm == NULL))
		goto out_err;

	cl_stk = &state->cl_stk;
	cl_stk->sp = max_conn;	/* Stack growsdown, so start from high */
	cl_stk->max_sp = max_conn;
	cl_stk->arr = stack_arr;

	for (uint16_t i = 0; i < max_conn; i++)
		tcp_client_init(clients + i, i);

	for (uint16_t i = 0; i < EPT_MAP_SIZE; i++)
		ept_map[i] = EPT_MAP_NOP;

	for (uint16_t i = 0; i < 256u; i++) {
		for (uint16_t j = 0; j < 256u; j++) {
			ipm[i][j] = NULL;
		}
	}

	state->epm_fd   = -1;
	state->ept_fd   = -1;
	state->net_fd   = -1;
	state->tun_fd   = -1;
	state->stop     = false;
	state->reconn   = true;
	state->reconn_c = 0;
	state->ept_map  = ept_map;
	state->ipm      = ipm;
	state->clients  = clients;
	return 0;

out_err:
	err = errno;
	free(clients);
	free(stack_arr);
	free(ept_map);
	pr_err("calloc: Cannot allocate memory: " PRERF, PREAR(err));
	return -ENOMEM;
}


static void destroy_state(struct srv_tcp_state *state)
{
	int epm_fd = state->epm_fd;
	int ept_fd = state->ept_fd;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = state->cfg->sock.max_conn;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(net_fd != -1)) {
		prl_notice(0, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	if (likely(epm_fd != -1)) {
		prl_notice(0, "Closing state->epm_fd (%d)", epm_fd);
		close(epm_fd);
	}

	if (likely(ept_fd != -1)) {
		prl_notice(0, "Closing state->ept_fd (%d)", ept_fd);
		close(ept_fd);
	}

	if (unlikely(clients != NULL)) {
		while (likely(max_conn--)) {
			struct tcp_client *client = clients + max_conn;

			if (likely(client->mt_act)) {
				pthread_mutex_lock(&client->mutex);
			}

			if (unlikely(!client->is_used))
				continue;
			
			prl_notice(6, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);

			if (likely(client->mt_act)) {
				pthread_mutex_unlock(&client->mutex);
				pthread_mutex_destroy(&client->mutex);
			}
		}
	}

	free(state->ipm);
	free(state->clients);
	free(state->ept_map);
	free(state->cl_stk.arr);

	state->ipm = NULL;
	state->clients = NULL;
	state->ept_map = NULL;
	state->cl_stk.arr = NULL;
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, interrupt_handler);
	signal(SIGINT, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGQUIT, interrupt_handler);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	// retval = init_iface(&state);
	// if (unlikely(retval < 0))
	// 	goto out;
	// retval = init_socket(&state);
	// if (unlikely(retval < 0))
	// 	goto out;
	// retval = init_epoll(&state);
	// if (unlikely(retval < 0))
	// 	goto out;
	// prl_notice(0, "Initialization Sequence Completed");
	// retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}

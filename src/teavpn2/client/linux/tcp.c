
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <sys/sysinfo.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/client/tcp.h>


struct cli_tcp_state {
	pid_t			pid;		/* Main process PID           */
	int			tcpu;		/* CPU number used by thread  */
	int			epm_fd;		/* Epoll fd (main)            */
	int			ept_fd;		/* Epoll fd (thread)          */
	int			net_fd;		/* Main TCP socket fd         */
	int			tun_fd;		/* TUN/TAP fd                 */
	int			pipe_fd[2];	/* Pipe fd                    */
	bool			stop;		/* Stop the event loop?       */
	bool			mt_act;		/* Is mutex need to be freed? */
	bool			reconn;		/* Reconnect if conn dropped? */
	bool			mutex_own;	/* true=thread; false=main    */
	uint8_t			reconn_c;	/* Reconnect count            */
	struct_pad(0, 3);
	struct cli_cfg		*cfg;		/* Config                     */
	pthread_t		thread;		/* Thread                     */
	pthread_mutex_t		mutex;		/* Mutex is mutex             */
};


static struct cli_tcp_state *g_state;


static void interrupt_handler(int sig)
{
	struct cli_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int init_state(struct cli_tcp_state *state)
{
	(void)state;
	return 0;
	// int err;
	// cpu_set_t affinity;

	// state->stop = false;
	// state->is_auth = false;
	// state->net_fd = -1;
	// state->tun_fd = -1;
	// state->epl_fd = -1;
	// state->send_c = 0;
	// state->recv_c = 0;
	// state->recv_s = 0;
	// state->read_c = 0;
	// state->write_c = 0;

	// CPU_ZERO(&affinity);
	// CPU_SET(0, &affinity);
	// if (sched_setaffinity(0, sizeof(cpu_set_t), &affinity) < 0) {
	// 	err = errno;
	// 	pr_error("sched_setaffinity: " PRERR, PREAG(err));
	// }

	// errno = 0;
	// if (nice(-20)) {
	// 	err = errno;
	// 	if (err != 0)
	// 		pr_error("nice: " PRERR, PREAG(err));
	// }

	// return 0;
}


int teavpn_client_tcp_handler(struct cli_cfg *cfg)
{
	int retval = 0;
	struct cli_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct cli_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, interrupt_handler);
	signal(SIGINT, interrupt_handler);
	signal(SIGPIPE, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGQUIT, interrupt_handler);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;



out:
	return retval;
}


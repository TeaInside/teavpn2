
#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <teavpn2/client/linux/tcp.h>
#include <teavpn2/client/linux/iface.h>

#define MAX_ERR_COUNT (15u)
static struct cli_tcp_state *state_g = NULL;

int teavpn_tcp_client(struct cli_cfg *cfg)
{

}

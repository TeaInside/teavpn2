
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <teavpn2/server/linux/tcp.h>
#include <teavpn2/server/linux/iface.h>
#include <teavpn2/global/helpers/linux/fd.h>
#include <teavpn2/global/helpers/linux/iface.h>

int teavpn_tcp_init_iface(struct srv_tcp_state *state)
{
	int fd;
	uint16_t i;
	struct srv_cfg *cfg = state->cfg;
	struct srv_iface_cfg *iface = &cfg->iface;
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = cfg->sock.max_conn;

	prl_notice(3, "Allocating virtual network interface...");
	for (i = 0; i < max_conn; i++) {

		prl_notice(6, "Allocating TUN fd (seq:%u)...", i);
		fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);
		if (fd < 0) {
			pr_error("Cannot allocate virtual iface: i = %u", i);
			goto out_err;
		}

		if (fd_set_nonblock(fd) < 0) {
			pr_error("fd_set_nonblock(): %s", strerror(errno));
			goto out_close_fd_err;
		}

		if (tun_set_queue(fd, false) < 0) {
			pr_error("Error tun_set_queue(): %s", strerror(errno));
			goto out_close_fd_err;
		}

		clients[i].tun_fd = fd;
		prl_notice(6, "Virtual iface allocated successfully (fd:%d) "
			   "(seq:%u)", fd, i);
		continue;

	out_close_fd_err:
		close(fd);
		goto out_err;
	}

	if (!raise_up_iface(iface))
		goto out_err;

	return 0;

out_err:
	/* Close opened file descriptors due to error*/
	if (i > 0) {
		prl_notice(3, "Closing opened tun_fd(s)...");
		while (i-- > 0) {
			prl_notice(6, "Closing tun_fd %d...", i);
			close(clients[i].tun_fd);
			clients[i].tun_fd = -1;
		}
	}
	return -1;
}

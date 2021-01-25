
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/if_tun.h>
#include <teavpn2/server/plat/linux/tcp.h>
#include <teavpn2/global/helpers/plat/linux/fd.h>
#include <teavpn2/global/helpers/plat/linux/iface.h>


int init_iface_tcp_server(struct srv_tcp_state *state)
{
	uint16_t i;
	struct srv_cfg *cfg = state->cfg;
	struct srv_iface_cfg *iface = &(cfg->iface);
	uint16_t max_conn = cfg->sock.max_conn;
	struct tcp_client *clients = state->clients;

	prl_notice(3, "Allocating virtual network interface...");

	for (i = 0; i < max_conn; i++) {
		int fd;

		prl_notice(3, "Allocating TUN fd (seq:%u)...", i);

		fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);

		if (fd < 0) {
			pr_error("Cannot allocate network interface: i = %u", i);
			goto out_err;
		}

		if (fd_set_nonblock(fd) < 0) {
			pr_error("fd_set_nonblock(): %s", strerror(errno));
			close(fd);
			goto out_err;
		}


		if (tun_set_queue(fd, false) < 0) {
			pr_error("Error tun_set_queue(): %s", strerror(errno));
			close(fd);
			goto out_err;
		}

		prl_notice(3, "TUN fd allocated successfully (fd:%d) (seq:%u)",
			   fd, i);

		clients[i].tun_fd = fd;
	}

	return 0;
out_err:
	/* Close opened file descriptors. */
	if (i > 0) {
		prl_notice(5, "Closing opened tun_fd(s)...");

		while (i-- > 0) {
			prl_notice(5, "Closing tun_fd %d...", i);
			close(clients[i].tun_fd);
			clients[i].tun_fd = -1;
		}
	}
	return -1;
}

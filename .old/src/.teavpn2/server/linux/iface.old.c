
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>

#include <teavpn2/server/linux/tcp.h>
#include <teavpn2/global/helpers/shell.h>
#include <teavpn2/global/helpers/string.h>
#include <teavpn2/global/helpers/linux/fd.h>
#include <teavpn2/global/helpers/linux/iface.h>


#define EXEC_CMD(OUT, BUF, CMD, ...)				\
do {								\
	snprintf((BUF), sizeof((BUF)), (CMD), __VA_ARGS__);	\
	prl_notice(3, "Executing: %s", (BUF));			\
	OUT = system((BUF));					\
} while (0)


#define IPV4SAFE (IPV4LEN + 16)


static inline char *simple_esc_arg(char *buf, const char *str)
{
	return escapeshellarg(buf, str, strlen(str), NULL);
}


static inline bool raise_up_interface(struct srv_iface_cfg *iface)
{
	/* User data */
	char u_ipv4[IPV4SAFE] = {0};
	char u_ipv4_netmask[IPV4SAFE] = {0};
	char u_ipv4_network[IPV4SAFE] = {0};
	char u_ipv4_broadcast[IPV4SAFE] = {0};

	/* Escaped data */
	char e_dev[32] = {0};
	char e_ipv4[IPV4SAFE] = {0};
	// char e_ipv4_netmask[IPV4SAFE];
	char e_ipv4_network[IPV4SAFE] = {0};
	char e_ipv4_broadcast[IPV4SAFE] = {0};

	/* Big endian data */
	__be32 tmp = 0;
	__be32 b_ipv4 = 0;
	__be32 b_ipv4_network = 0;
	__be32 b_ipv4_netmask = 0;
	__be32 b_ipv4_broadcast = 0;

	int ret = 0;
	uint8_t cidr = 0;
	char buf[1024] = {0};
	uint16_t mtu = iface->mtu;


	strncpy(u_ipv4, iface->ipv4, sizeof(u_ipv4) - 1);
	strncpy(u_ipv4_netmask, iface->ipv4_netmask,
		sizeof(u_ipv4_netmask) - 1);


	/* Convert netmask from chars to big endian integer */
	if (!inet_pton(AF_INET, u_ipv4_netmask, &b_ipv4_netmask)) {
		pr_error("inet_pton(\"%s\"): ipv4_netmask: %s", u_ipv4_netmask,
			 strerror(errno));
		return false;
	}


	/* Convert netmask from big endian integer to CIDR */
	tmp = b_ipv4_netmask;
	cidr = 0;
	while (tmp) {
		cidr++;
		tmp >>= 1;
	}

	if (cidr > 32) {
		pr_error("Invalid converted CIDR: %d from \"%s\"", cidr,
			 u_ipv4_netmask);
		return false;
	}


	/* Convert IPv4 from chars to big endian integer. */
	if (!inet_pton(AF_INET, u_ipv4, &b_ipv4)) {
		pr_error("inet_pton(\"%s\"): ipv4: %s", u_ipv4,
			 strerror(errno));
		return false;
	}

	/* Add CIDR to IPv4 */
	sprintf(u_ipv4 + strlen(u_ipv4), "/%d", cidr);

	 /* Bitwise AND between IP address and netmask
	  * will result in network address.
	  */
	b_ipv4_network = (b_ipv4 & b_ipv4_netmask);


	/* A bitwise OR between network address and inverted
	 * netmask will give the broadcast address.
	 */
	b_ipv4_broadcast = b_ipv4_network | (~b_ipv4_netmask);


	/* Convert network address from big endian integer to chars */
	if (!inet_ntop(AF_INET, &b_ipv4_network, u_ipv4_network,
		       sizeof(u_ipv4_network))) {
		pr_error("inet_ntop(%x): u_ipv4_network: %s", b_ipv4_network,
			 strerror(errno));
		return false;
	}

	/* Add CIDR to network address */
	sprintf(u_ipv4_network + strlen(u_ipv4_network), "/%d", cidr);


	/* Convert broadcast address from big endian integer to chars */
	if (!inet_ntop(AF_INET, &b_ipv4_broadcast, u_ipv4_broadcast,
		       sizeof(u_ipv4_broadcast))) {
		pr_error("inet_ntop(%x): u_ipv4_broadcast: %s",
			 u_ipv4_broadcast, strerror(errno));
		return false;
	}

	simple_esc_arg(e_ipv4_network, u_ipv4_network);
	simple_esc_arg(e_ipv4_broadcast, u_ipv4_broadcast);
	simple_esc_arg(e_dev, iface->dev);
	simple_esc_arg(e_ipv4, u_ipv4);

	EXEC_CMD(ret, buf, "/sbin/ip link set dev %s up mtu %d", e_dev, mtu);
	if (ret < 0)
		return false;

	EXEC_CMD(ret, buf, "/sbin/ip addr add dev %s %s broadcast %s", e_dev,
		 e_ipv4, e_ipv4_broadcast);
	if (ret < 0)
		return false;

	return true;
}


int init_iface_tcp_server(struct srv_tcp_state *state)
{
	int fd;
	uint16_t i;
	struct srv_cfg *cfg = state->cfg;
	uint16_t max_conn = cfg->sock.max_conn;
	struct srv_iface_cfg *iface = &(cfg->iface);
	struct tcp_client *clients = state->clients;

	prl_notice(3, "Allocating virtual network interface...");

	for (i = 0; i < max_conn; i++) {

		prl_notice(3, "Allocating TUN fd (seq:%u)...", i);

		fd = tun_alloc(iface->dev, IFF_TUN | IFF_MULTI_QUEUE);
		if (fd < 0) {
			pr_error("Cannot allocate network interface: i = %u",
				 i);
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
		prl_notice(3, "TUN fd allocated successfully (fd:%d) (seq:%u)",
			   fd, i);

		clients[i].tun_fd = fd;
		continue;

	out_close_fd_err:
		close(fd);
		goto out_err;
	}

	if (!raise_up_interface(iface))
		goto out_err;

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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/net/linux/iface.h>



/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */
int tun_alloc(const char *dev, int flags)
{
	int fd;
	int retval;
	struct ifreq ifr;
	static bool retried = false;
	static const char *tun_dev = "/dev/net/tun";

	if ((dev == NULL) || (*dev == '\0')) {
		pr_error("Error tun_alloc(): dev cannot be empty");
		return -EINVAL;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_flags = flags;
	fd = open(tun_dev, O_RDWR);
	if (unlikely(fd < 0)) {
		int ern = errno;

		if ((!retried) && (ern == ENOENT)) {
			prl_notice(4, "open(%s): %s", tun_dev, strerror(ern));
			retried = !retried;
			tun_dev = "/dev/tun";
			prl_notice(4, "Set dev_tun fallback to %s", tun_dev);
			return tun_alloc(dev, flags);
		}

		pr_error("open(%s): %s", tun_dev, strerror(ern));
		return fd;
	}

	retval = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if (unlikely(retval < 0)) {
		pr_error("ioctl(%d, TUNSETIFF): %s", fd, strerror(errno));
		close(fd);
		return retval;
	}

	return fd;
}


int tun_set_queue(int fd, bool enable)
{
	int retval;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_flags = enable ? IFF_ATTACH_QUEUE : IFF_DETACH_QUEUE;

	retval = ioctl(fd, TUNSETQUEUE, (void *)&ifr);
	if (retval < 0)
		pr_error("ioctl(%d, TUNSETQUEUE): %s", fd, strerror(errno));

	return retval;
}


/**
* @param int fd
* @return int
*/
int fd_set_nonblock(int fd)
{
	int flags;

	/* If they have O_NONBLOCK, use the POSIX way to do it */
#if defined(O_NONBLOCK)

	/*
	 * Fixme:
	 * O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5.
	 */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}


#define IPV4SAFE (IPV4LEN + 16)
#define EXEC_CMD(OUT, BUF, CMD, ...)				\
do {								\
	snprintf((BUF), sizeof((BUF)), (CMD), __VA_ARGS__);	\
	prl_notice(3, "Executing: %s", (BUF));			\
	OUT = system((BUF));					\
} while (0)


static __always_inline char *simple_esc_arg(char *buf, const char *str)
{
	return escapeshellarg(buf, str, strlen(str), NULL);
}

bool raise_up_interface(struct iface_cfg *iface)
{
	/* User data */
	char u_ipv4[IPV4SAFE + 1] = {0};
	char u_ipv4_netmask[IPV4SAFE + 1] = {0};
	char u_ipv4_network[IPV4SAFE + 1] = {0};
	char u_ipv4_broadcast[IPV4SAFE + 1] = {0};

	/* Escaped data */
	char e_dev[32] = {0};
	char e_ipv4[IPV4SAFE + 1] = {0};
	char e_ipv4_network[IPV4SAFE + 1] = {0};
	char e_ipv4_broadcast[IPV4SAFE + 1] = {0};

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

	strncpy(u_ipv4, iface->ipv4, IPV4SAFE);
	strncpy(u_ipv4_netmask, iface->ipv4_netmask, IPV4SAFE);

	/* Convert netmask from chars to big endian integer */
	if (!inet_pton(AF_INET, u_ipv4_netmask, &b_ipv4_netmask)) {
		pr_error("inet_pton(%s): ipv4_netmask: %s", u_ipv4_netmask,
			 strerror(errno));
		return false;
	}

	/* Convert netmask from big endian integer to CIDR */
	cidr = 0;
	tmp = b_ipv4_netmask;
	while (tmp) {
		cidr++;
		tmp >>= 1;
	}

	if (cidr > 32) {
		pr_error("Invalid converted CIDR: %d from \"%s\"", cidr,
			 u_ipv4_netmask);
		return false;
	}

	/* Convert IPv4 from chars to big endian integer */
	if (!inet_pton(AF_INET, u_ipv4, &b_ipv4)) {
		pr_error("inet_pton(%s): ipv4: %s", u_ipv4, strerror(errno));
		return false;
	}

	/* Add CIDR to IPv4 */
	snprintf(u_ipv4 + strnlen(u_ipv4, IPV4SAFE), IPV4SAFE, "/%d", cidr);


	/* Bitwise AND between IP address and netmask
	 * will result in network address.
	 */
	b_ipv4_network = (b_ipv4 & b_ipv4_netmask);

	/* A bitwise OR between network address and inverted
	 * netmask will give the broadcast address.
	 */
	b_ipv4_broadcast = b_ipv4_network | (~b_ipv4_netmask);

	/* Convert network address from big endian integer to chars */
	if (!inet_ntop(AF_INET, &b_ipv4_network, u_ipv4_network, IPV4SAFE)) {
		pr_error("inet_ntop(%x): u_ipv4_network: %s", b_ipv4_network,
			 strerror(errno));
		return false;
	}

	/* Add CIDR to network address */
	snprintf(u_ipv4_network + strnlen(u_ipv4_network, IPV4SAFE), IPV4SAFE,
		 "/%d", cidr);

	/* Convert broadcast address from big endian integer to chars */
	if (!inet_ntop(AF_INET, &b_ipv4_broadcast, u_ipv4_broadcast,
		       IPV4SAFE)) {
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

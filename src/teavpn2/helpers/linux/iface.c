
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <teavpn2/global/common.h>

#include <teavpn2/global/helpers/linux/iface.h>

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
	int fd, retval;
	struct ifreq ifr;
	static bool retried = false;
	static const char *tun_dev = "/dev/net/tun";

	if ((!dev) || (!*dev)) {
		pr_error("Error tun_alloc(): dev cannot be empty");
		return -EINVAL;
	}

	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_flags = flags;


	fd = open(tun_dev, O_RDWR);
	if (fd < 0) {
		int tmp_err = errno;

		if ((!retried) && (tmp_err == ENOENT)) {
			prl_notice(3, "open(\"%s\"): %s", tun_dev,
				   strerror(tmp_err));

			retried = !retried;
			tun_dev = "/dev/tun";

			prl_notice(3, "Set fallback to %s", tun_dev);
			return tun_alloc(dev, flags);
		}

		pr_error("open(\"%s\"): %s", tun_dev, strerror(tmp_err));
		return fd;
	}

	retval = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if (retval < 0) {
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

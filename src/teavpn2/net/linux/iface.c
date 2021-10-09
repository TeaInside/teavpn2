// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Network interface functions for TeaVPN2 (Linux)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

#include <teavpn2/common.h>
#include <teavpn2/net/linux/iface.h>

#include <ctype.h>


static __always_inline int is_ws(int the_chr)
{
	return isspace((int)((unsigned)the_chr));
}


static noinline char *strtriml_move(char *str, size_t len)
{
	size_t trimmed_len;
	char *orig = str, *end;

	if (unlikely(len == 0))
		return orig;


	/*
	 * We assume that `str + len` is the location of the NUL char
	 */
	end = str + len - 1;


	while (is_ws(*str)) {

		if (str == &end[1]) {
			*orig = '\0';
			return orig;
		}

		str++;
	}


	if (*str == '\0' && str == &end[1]) {
		/*
		 * All spaces C string, or empty C string will go here.
		 */
		*orig = '\0';
		return orig;
	}


	while (is_ws(*end))
		end--;


	trimmed_len = (size_t)(end - str) + 1u;
	if (orig != str)
		memmove(orig, str, trimmed_len);

	orig[trimmed_len] = '\0';
	return orig;
}



static noinline char *strtrim_move(char *str)
{
	/* TODO: Don't waste time just for strlen */
	return strtriml_move(str, strlen(str));
}


static char *sane_strncpy(char *__restrict__ dst, char *__restrict__ src,
			  size_t len)
{
	strncpy(dst, src, len);
	dst[len - 1] = '\0';
	return dst;
}


/*
 *
 * Thanks to PHP
 * https://github.com/php/php-src/blob/e9d78339e7ff2edb8a1eda93d047ccaac25efa24/ext/standard/exec.c#L388-L468
 *
 */
static noinline char *escapeshellarg(char *alloc, const char *str,
					size_t len, size_t *res_len)
{
	size_t y = 0;
	size_t l = (len > 0) ? len : strlen(str);
	size_t x;
	char *cmd;

	if (alloc == NULL)
		/* Worst case */
		cmd = (char *)malloc((sizeof(char) * l * 4) + 1);
	else
		cmd = alloc;

#ifdef WIN32
	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif

	for (x = 0; x < l; x++) {
		switch (str[x]) {
#ifdef WIN32
		case '"':
		case '%':
		case '!':
			cmd[y++] = ' ';
			break;
#else
		case '\'':
			cmd[y++] = '\'';
			cmd[y++] = '\\';
			cmd[y++] = '\'';
#endif
		fallthrough;
		default:
			cmd[y++] = str[x];
		}
	}

#ifdef WIN32
	if (y > 0 && '\\' == cmd[y - 1]) {
		int k = 0, n = y - 1;
		for (; n >= 0 && '\\' == cmd[n]; n--, k++);
		if (k % 2) {
			cmd[y++] = '\\';
		}
	}
	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif

	cmd[y] = '\0';

	if (res_len != NULL)
		*res_len = y;

	return cmd;
}



/* https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */
int tun_alloc(const char *dev, short flags)
{
	int fd;
	int err;
	struct ifreq ifr;
	bool retried = false;
	static const char *dtf = "/dev/net/tun";

	if (unlikely((dev == NULL) || (*dev == '\0'))) {
		pr_error("tun_alloc(): dev cannot be empty");
		return -EINVAL;
	}

again:
	fd = open(dtf, O_RDWR);
	if (unlikely(fd < 0)) {
		err = errno;
		pr_err("open(\"%s\", O_RDWR): " PRERF, dtf, PREAR(err));

		if ((!retried) && (err == ENOENT)) {
			/*
			 * On android, it is located at /dev/tun
			 */
			dtf = "/dev/tun";
			retried = !retried;
			prl_notice(0, "Set fallback to %s", dtf);
			goto again;
		}

		return -err;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	strtrim_move(ifr.ifr_name);
	ifr.ifr_flags = flags;

	if (unlikely(ioctl(fd, TUNSETIFF, &ifr) < 0)) {
		close(fd);
		err = errno;
		pr_err("ioctl(%d, TUNSETIFF, &ifr): " PRERF, fd, PREAR(err));
		return -err;
	}

	return fd;
}


int fd_set_nonblock(int fd)
{
	int err;
	int flags;

	/*
	 * Fixme:
	 * O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5.
	 */
	flags = fcntl(fd, F_GETFL, 0);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_GETFL, 0): " PRERF, fd, PREAR(err));
		return -err;
	}

	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_SETFL, %d): " PRERF, fd, flags, PREAR(err));
		return -err;
	}

	return flags;
}




static char *shell_exec(const char *cmd, char *buf, size_t buflen,
			size_t *outlen)
{
	int err;
	FILE *handle;
	bool use_malloc;
	size_t read_len;

	use_malloc = (buf == NULL);

	if (unlikely(use_malloc)) {
		buf = malloc(buflen);
		if (unlikely(buf == NULL)) {
			err = errno;
			pr_err("malloc(): " PRERF, PREAR(err));
			goto out_err;
		}
	}

	handle = popen(cmd, "r");
	if (unlikely(handle == NULL)) {
		err = errno;
		pr_err("popen(\"%s\", \"r\"): " PRERF, cmd, PREAR(err));
		goto out_err;
	}

	memset(buf, 0, buflen);
	read_len = fread(buf, sizeof(char), buflen, handle);
	pclose(handle);

	if (likely(outlen))
		*outlen = read_len;

	return buf;
out_err:
	if (unlikely(use_malloc))
		free(buf);
	return NULL;
}



#define IPV4_EL (IPV4_L * 2)
#define IPV4_LI (IPV4_L + 1)
#define IPV4_ELI (IPV4_EL + 1)

#define EXEC_CMD(OUT, BUF, IP, CMD, ...)				\
do {									\
	int p = 0;							\
	char __cbuf[sizeof((BUF)) * 3];					\
	snprintf((BUF), sizeof((BUF)), (CMD), __VA_ARGS__);		\
	p = snprintf((__cbuf), sizeof(__cbuf), "%s %s", IP, ((BUF)));	\
	pr_notice("Executing: %s", (__cbuf));				\
	if (suppress_err)						\
		p += snprintf((__cbuf) + p,				\
			      sizeof(__cbuf) - (unsigned)p,		\
			      " >> /dev/null 2>&1");			\
	*(OUT) = system((__cbuf));					\
} while (0)


static __always_inline char *simple_esc_arg(char *buf, const char *str)
{
	return escapeshellarg(buf, str, strlen(str), NULL);
}


static __always_inline const char *find_ip_cmd(void)
{
	int ret;
	static const char * const ip_bin[] = {
		"/bin/ip",
		"/sbin/ip",
		"/usr/bin/ip",
		"/usr/sbin/ip",
		"/usr/local/bin/ip",
		"/usr/local/sbin/ip",
		"/data/data/com.termux/files/usr/bin/ip"
	};

	for (size_t i = 0; i < (sizeof(ip_bin) / sizeof(*ip_bin)); i++) {
		errno = 0;
		ret = access(ip_bin[i], R_OK | X_OK);
		prl_notice(0, "Locating %s: %s", ip_bin[i], strerror(errno));
		if (ret == 0)
			return ip_bin[i];
	}

	pr_err("Cannot find ip bin executable file");
	return NULL;
}

static noinline bool teavpn_iface_toggle(struct if_info *iface, bool up,
					    bool suppress_err);


bool teavpn_iface_up(struct if_info *iface)
{
	return teavpn_iface_toggle(iface, true, false);
}


bool teavpn_iface_down(struct if_info *iface)
{
	return teavpn_iface_toggle(iface, false, true);
}


static noinline bool teavpn_iface_toggle(struct if_info *iface, bool up,
					    bool suppress_err)
{
#ifdef TEAVPN_IPV6_SUPPORT
	static_assert(0, "Fixme: Handle IPv6 assignment.");
#endif
	int err;
	int ret;

	/* User data */
	char uipv4[IPV4_LI];
	char uipv4_nm[IPV4_LI];	/* Netmask   */
	char uipv4_nw[IPV4_LI];	/* Network   */
	char uipv4_bc[IPV4_LI];	/* Broadcast */

	/* Escaped data */
	char edev[sizeof(iface->dev) * 2];
	char eipv4[IPV4_ELI];
	char eipv4_nw[IPV4_ELI];	/* Network   */
	char eipv4_bc[IPV4_ELI];	/* Broadcast */

	/* 32-bit big-endian data */
	uint32_t tmp;
	uint32_t bipv4;
	uint32_t bipv4_nm;		/* Netmask   */
	uint32_t bipv4_nw;		/* Network   */
	uint32_t bipv4_bc;		/* Broadcast */

	uint8_t cidr;
	char cbuf[256];
	const char *ip;

	sane_strncpy(uipv4, iface->ipv4, sizeof(uipv4));
	sane_strncpy(uipv4_nm, iface->ipv4_netmask, sizeof(uipv4_nm));

	/* Convert netmask from chars to 32-bit big-endian integer */
	if (unlikely(!inet_pton(AF_INET, uipv4_nm, &bipv4_nm))) {
		err = errno;
		err = err ? err : EINVAL;
		pr_err("inet_pton(%s): uipv4_nm: " PRERF, uipv4_nm, PREAR(err));
		return false;
	}

	/* Convert netmask from 32-bit big-endian integer to CIDR number */
	cidr = 0;
	tmp  = bipv4_nm;
	while (tmp) {
		cidr++;
		tmp >>= 1;
	}

	if (unlikely(cidr > 32)) {
		pr_err("Invalid CIDR: %d from \"%s\"", cidr, uipv4_nm);
		return false;
	}

	/* Convert IPv4 from chars to big endian integer */
	if (unlikely(!inet_pton(AF_INET, uipv4, &bipv4))) {
		err = errno;
		err = err ? err : EINVAL;
		pr_error("inet_pton(%s): uipv4: " PRERF, uipv4, PREAR(err));
		return false;
	}

	/* Add CIDR to IPv4 */
	snprintf(uipv4 + strnlen(uipv4, IPV4_L), IPV4_L, "/%u", cidr);

	/*
	 * Bitwise AND between IP address and netmask
	 * will result in network address.
	 */
	bipv4_nw = bipv4 & bipv4_nm;

	/*
	 * A bitwise OR between network address and inverted
	 * netmask will give the broadcast address.
	 */
	bipv4_bc = bipv4_nw | (~bipv4_nm);

	/* Convert network address from 32-bit big-endian integer to chars */
	if (unlikely(!inet_ntop(AF_INET, &bipv4_nw, uipv4_nw, IPV4_L))) {
		err = errno;
		err = err ? err : EINVAL;
		pr_error("inet_ntop(%" PRIx32 "): bipv4_nw: " PRERF, bipv4_nw,
			 PREAR(err));
		return false;
	}

	/* Add CIDR to network address */
	snprintf(uipv4_nw + strnlen(uipv4_nw, IPV4_L), IPV4_L, "/%d", cidr);

	/* Convert broadcast address from 32-bit big-endian integer to chars */
	if (!inet_ntop(AF_INET, &bipv4_bc, uipv4_bc, IPV4_L)) {
		err = errno;
		err = err ? err : EINVAL;
		pr_error("inet_ntop(%" PRIx32 "): bipv4_bc: " PRERF, bipv4_bc,
			 PREAR(err));
		return false;
	}

	simple_esc_arg(eipv4, uipv4);
	simple_esc_arg(eipv4_nw, uipv4_nw);
	simple_esc_arg(eipv4_bc, uipv4_bc);
	simple_esc_arg(edev, iface->dev);

	ip = find_ip_cmd();
	if (ip == NULL)
		return false;

	EXEC_CMD(&ret, cbuf, ip, "link set dev %s %s mtu %d", edev,
		 (up ? "up" : "down"), iface->ipv4_mtu);

	if (unlikely(ret != 0))
		return false;

	EXEC_CMD(&ret, cbuf, ip, "addr %s dev %s %s broadcast %s",
		 (up ? "add" : "delete"), edev, eipv4, eipv4_bc);

	if (unlikely(ret != 0))
		return false;

	if (likely(*iface->ipv4_pub != '\0')) {
		char *tmpc;
		char *rdgw;
		char *ipv4_pub = iface->ipv4_pub;
		char *erdgw = eipv4;		/* Reuse buffer */
		char *eipv4_pub = eipv4_nw;	/* Reuse buffer */
		char tmpbuf[128];

		snprintf(tmpbuf, sizeof(tmpbuf), "%s route show", ip);

		/* Get real default gateway */
		shell_exec(tmpbuf, cbuf, sizeof(cbuf) - 1, NULL);

		rdgw = cbuf;
		rdgw[sizeof(cbuf) - 1] = '\0';
		rdgw = strstr(rdgw, "default via ");

		if (unlikely(rdgw == NULL)) {
			pr_err("Can't find default gateway from command: %s "
			       "route show", ip);
			return false;
		}

		rdgw += sizeof("default via ") - 1;

		/* Just cut */
		tmpc = rdgw;
		while ((*tmpc != ' ') && (*tmpc != '\0') && (*tmpc != '\n'))
			tmpc++;
		*tmpc = '\0';

		simple_esc_arg(erdgw, rdgw);
		simple_esc_arg(eipv4_pub, ipv4_pub);

		if (up) {
			int tmp_ret;
			char __tmp[128];
			snprintf(__tmp, sizeof(__tmp),
				 "%s route delete %s/32 via %s >> /dev/null 2>&1",
				 ip, eipv4_pub, erdgw);
			tmp_ret = system(__tmp);
			(void)tmp_ret;
		}


		/* We have the real default gateway in rdgw */
		EXEC_CMD(&ret, cbuf, ip, "route %s %s/32 via %s",
			 (up ? "add" : "delete"), eipv4_pub, erdgw);

		if (unlikely(ret != 0))
			return false;


		if (likely(*iface->ipv4_dgateway != '\0')) {
			char *edgw = eipv4;	/* Reuse buffer */

			simple_esc_arg(edgw, iface->ipv4_dgateway);

			EXEC_CMD(&ret, cbuf, ip, "route %s 0.0.0.0/1 via %s",
				 (up ? "add" : "delete"), edgw);

			if (unlikely(ret != 0))
				return false;

			EXEC_CMD(&ret, cbuf, ip, "route %s 128.0.0.0/1 via %s",
				 (up ? "add" : "delete"), edgw);

			if (unlikely(ret != 0))
				return false;
		}
	}

	#undef IP

	return true;
}

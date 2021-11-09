// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <ctype.h>
#include <getopt.h>
#include <inih/inih.h>
#include <teavpn2/server/common.h>

struct cfg_parse_ctx {
	struct srv_cfg	*cfg;
};


/*
 * Default config.
 */
static const int d_srv_backlog = 10;
static const uint16_t d_srv_bind_port = 44444;
static const uint16_t d_srv_mtu = 1450;
static const char d_srv_dev[] = "tsrv0";
static const char d_srv_ipv4[] = "10.5.5.1";
static const char d_srv_ipv4_netmask[] = "255.255.255.0";
static const char d_srv_cfg_file[] = "/etc/teavpn2/server.ini";
static const uint8_t d_num_of_threads = 2;
static const uint16_t d_srv_max_conn = 32;


static __cold void set_default_config(struct srv_cfg *cfg)
{
	struct srv_cfg_sys *sys = &cfg->sys;
	struct srv_cfg_sock *sock = &cfg->sock;
	struct srv_cfg_iface *iface = &cfg->iface;

	sys->cfg_file = d_srv_cfg_file;
	sys->thread_num = d_num_of_threads;

	iface->iff.ipv4_mtu = d_srv_mtu;
	strncpy2(iface->dev, d_srv_dev, sizeof(iface->dev));
	strncpy2(iface->iff.dev, d_srv_dev, sizeof(iface->iff.dev));
	strncpy2(iface->iff.ipv4, d_srv_ipv4, sizeof(iface->iff.ipv4));
	strncpy2(iface->iff.ipv4_netmask, d_srv_ipv4_netmask,
		 sizeof(iface->iff.ipv4_netmask));


	strncpy2(sock->bind_addr, "0.0.0.0", sizeof(cfg->sock.bind_addr));
	sock->bind_port = d_srv_bind_port;
	sock->backlog = d_srv_backlog;
	sock->max_conn = d_srv_max_conn;
}


static __cold void teavpn_server_show_help(const char *app)
{
	printf("Usage: %s server [options]\n", app);

	printf("\n");
	printf("TeaVPN Server Application\n");
	printf("\n");
	printf("Available options:\n");
	printf("  -h, --help\t\t\tShow this help message.\n");
	printf("  -V, --version\t\t\tShow application version.\n");
	printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
	       d_srv_cfg_file);
	printf("  -d, --data-dir=DIR\t\tSet data directory.\n");
	printf("  -t, --thread=N\t\tSet number of threads (default: %hhu).\n",
	       d_num_of_threads);

	printf("\n");
	printf("[Config options]\n");
	printf(" Virtual network interface:\n");
	printf("  -D, --dev=DEV\t\t\tSet virtual network interface name"
	       " (default: %s).\n", d_srv_dev);
	printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n",
	       d_srv_mtu);
	printf("  -4, --ipv4=IP\t\t\tSet IPv4 (default: %s).\n", d_srv_ipv4);
	printf("  -N, --ipv4-netmask=MASK\tSet IPv4 netmask (default: %s).\n",
	       d_srv_ipv4_netmask);
#ifdef TEAVPN_IPV6_SUPPORT
	printf("  -6, --ipv6=IP\t\t\tSet IPv6 (default: %s).\n", "???");
	printf("  -M, --ipv6-netmask=MASK\tSet IPv6 netmask (default: %s).\n",
	       "???");
#endif


	printf("\n");
	printf(" Socket:\n");
	printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
	       " (default: tcp).\n");
	printf("  -H, --bind-addr=IP\t\tSet bind address (default 0.0.0.0).\n");
	printf("  -P, --bind-port=PORT\t\tSet bind port (default: %d).\n",
	       d_srv_bind_port);
	printf("  -k, --max-conn=N\t\tSet max connections (default: %d).\n",
	       d_srv_max_conn);
	printf("  -B, --backlog=N\t\tSet socket listen backlog (default: %d)"
	       ".\n", d_srv_backlog);
	printf("  -C, --ssl-cert=FILE\t\tSet SSL certificate.\n");
	printf("  -K, --ssl-priv-key=FILE\tSet SSL private key.\n");

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on the GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under GNU GPL-v2 license.\n");
}


#define PR_CFG(C, FMT) printf("   " #C " = " FMT "\n", C)


static __maybe_unused void dump_server_cfg(struct srv_cfg *cfg)
{
	puts("=============================================");
	puts("   Config dump   ");
	puts("=============================================");
	PR_CFG(cfg->sys.cfg_file, "%s");
	PR_CFG(cfg->sys.data_dir, "%s");
	PR_CFG(cfg->sys.thread_num, "%hhu");
	PR_CFG(cfg->sys.verbose_level, "%hhu");
	putchar('\n');
	printf("   cfg->sock.use_encryption = %hhu\n",
		(uint8_t)cfg->sock.use_encryption);
	printf("   cfg->sock.type = %s\n",
		(cfg->sock.type == SOCK_TCP) ? "SOCK_TCP" :
		((cfg->sock.type == SOCK_UDP) ? "SOCK_UDP" : "unknown"));
	PR_CFG(cfg->sock.bind_addr, "%s");
	PR_CFG(cfg->sock.bind_port, "%hu");
	PR_CFG(cfg->sock.event_loop, "%s");
	PR_CFG(cfg->sock.max_conn, "%hu");
	PR_CFG(cfg->sock.ssl_cert, "%s");
	PR_CFG(cfg->sock.ssl_priv_key, "%s");
	putchar('\n');
	PR_CFG(cfg->iface.dev, "%s");
	PR_CFG(cfg->iface.mtu, "%hu");
	PR_CFG(cfg->iface.iff.ipv4, "%s");
	PR_CFG(cfg->iface.iff.ipv4_netmask, "%s");
	puts("=============================================");
}

/* TODO: Write my own getopt function. */

static const struct option long_options[] = {
	/* Help, version and verbose. */
	{"help",           no_argument,       0, 'h'},
	{"version",        no_argument,       0, 'V'},
	{"verbose",        optional_argument, 0, 'v'},

	/* Sys. */
	{"config",         required_argument, 0, 'c'},
	{"data-dir",       required_argument, 0, 'd'},
	{"thread",         required_argument, 0, 't'},

	/* Net. */
	{"dev",            required_argument, 0, 'D'},
	{"mtu",            required_argument, 0, 'm'},
	{"ipv4",           required_argument, 0, '4'},
	{"ipv4-netmask",   required_argument, 0, 'N'},

	/* Socket. */
	{"sock-type",      required_argument, 0, 's'},
	{"bind-addr",      required_argument, 0, 'H'},
	{"bind-port",      required_argument, 0, 'P'},
	{"backlog",        required_argument, 0, 'B'},
	{"encrypt",        no_argument,       0, 'E'},


	{0, 0, 0, 0}
};
static const char short_opt[] = "hVv::c:d:t:D:m:4:N:s:H:P:B:E:";

static __cold int parse_argv(int argc, char *argv[], struct srv_cfg *cfg)
{
	int c;
	struct srv_cfg_sys *sys = &cfg->sys;
	struct srv_cfg_sock *sock = &cfg->sock;
	struct srv_cfg_iface *iface = &cfg->iface;

	while (1) {
		int opt_idx = 0;

		c = getopt_long(argc, argv, short_opt, long_options, &opt_idx);
		if (c == -1)
			break;

		switch (c) {
		/* Help, version and verbose. */
		case 'h':
			teavpn_server_show_help(argv[0]);
			goto exit_zero;
		case 'V':
			show_version();
			goto exit_zero;
		case 'v': {
			uint8_t level = optarg ? (uint8_t)atoi(optarg) : 6u;
			set_notice_level(level);
			sys->verbose_level = level;
			break;
		}

		/* Sys */
		case 'c':
			sys->cfg_file = optarg;
			break;
		case 'd':
			strncpy2(sys->data_dir, optarg, sizeof(sys->data_dir));
			break;
		case 't':  {
			int tmp = atoi(optarg);
			if (tmp <= 0) {
				pr_err("Thread num argument must be greater than 0");
				return -EINVAL;
			}
			sys->thread_num = (uint8_t)tmp;
			break;
		}


		/* Net. */
		case 'D':
			strncpy2(iface->dev, optarg, sizeof(iface->dev));
			break;
		case 'm':  {
			int tmp = atoi(optarg);
			if (tmp <= 0) {
				pr_err("MTU must be greater than 0");
				return -EINVAL;
			}
			iface->mtu = (uint16_t)tmp;
			break;
		}
		case '4':
			strncpy2(iface->iff.ipv4, optarg, sizeof(iface->iff.ipv4));
			break;
		case 'N':
			strncpy2(iface->iff.ipv4_netmask, optarg,
				 sizeof(iface->iff.ipv4_netmask));
			break;

		/* Socket. */
		case 's':  {
			char tmp[5], *p = tmp;

			strncpy(tmp, optarg, sizeof(tmp));
			tmp[sizeof(tmp) - 1] = '\0';

			while (*p) {
				*p = (char)tolower((int)((unsigned)*p));
				p++;
			}

			if (!strcmp(tmp, "tcp")) {
				sock->type = SOCK_TCP;
			} else if (!strcmp(tmp, "udp")) {
				sock->type = SOCK_UDP;
			} else {
				pr_err("Invalid socket type: %s", optarg);
				return -EINVAL;
			}
			break;
		}
		case 'H':
			strncpy(sock->bind_addr, optarg, sizeof(sock->bind_addr));
			sock->bind_addr[sizeof(sock->bind_addr) - 1] = '\0';
			break;
		case 'P':
			sock->bind_port = (uint16_t)atoi(optarg);
			break;
		case 'E':
			sock->use_encryption = atoi(optarg) ? true : false;
			break;
		}
	}

	return 0;

exit_zero:
	exit(0);
	__builtin_unreachable();
}


static int cfg_parse_section_sys(struct cfg_parse_ctx *ctx, const char *name,
				 const char *val, int lineno)
{
	struct srv_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "thread")) {
		cfg->sys.thread_num = (uint8_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "verbose_level")) {
		uint8_t level = (uint8_t)strtoul(val, NULL, 10);
		set_notice_level(level);
		cfg->sys.verbose_level = level;
	} else if (!strcmp(name, "data_dir")) {
		strncpy2(cfg->sys.data_dir, val, sizeof(cfg->sys.data_dir));
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d", name,
			"sys", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


static int cfg_parse_section_socket(struct cfg_parse_ctx *ctx, const char *name,
				    const char *val, int lineno)
{
	struct srv_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "use_encryption")) {
		cfg->sock.use_encryption = atoi(val) ? true : false;
	} else if (!strcmp(name, "event_loop")) {
		strncpy2(cfg->sock.event_loop, val, sizeof(cfg->sock.event_loop));
	} else if (!strcmp(name, "sock_type")) {
		char tmp[8], *p = tmp;
		strncpy2(tmp, val, sizeof(tmp));
		while (*p) {
			*p = (char)tolower((int)((unsigned)*p));
			p++;
		}

		if (!strcmp(tmp, "tcp")) {
			cfg->sock.type = SOCK_TCP;
		} else if (!strcmp(tmp, "udp")) {
			cfg->sock.type = SOCK_UDP;
		} else {
			pr_err("Invalid socket type \"%s\" at %s:%d", val,
				cfg->sys.cfg_file, lineno);
			return 0;
		}
	} else if (!strcmp(name, "bind_addr")) {
		strncpy2(cfg->sock.bind_addr, val, sizeof(cfg->sock.bind_addr));
	} else if (!strcmp(name, "bind_port")) {
		cfg->sock.bind_port = (uint16_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "backlog")) {
		cfg->sock.backlog = atoi(val);
	} else if (!strcmp(name, "max_conn")) {
		cfg->sock.max_conn = (uint16_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "ssl_cert")) {
		strncpy2(cfg->sock.ssl_cert, val, sizeof(cfg->sock.ssl_cert));
	} else if (!strcmp(name, "ssl_priv_key")) {
		strncpy2(cfg->sock.ssl_priv_key, val, sizeof(cfg->sock.ssl_priv_key));
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d", name,
			"socket", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


static int cfg_parse_section_iface(struct cfg_parse_ctx *ctx, const char *name,
				   const char *val, int lineno)
{
	struct srv_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "dev")) {
		strncpy2(cfg->iface.dev, val, sizeof(cfg->iface.dev));
		cfg->iface.dev[sizeof(cfg->iface.dev) - 1] = '\0';
		strncpy2(cfg->iface.iff.dev, val, sizeof(cfg->iface.iff.dev));
		cfg->iface.iff.dev[sizeof(cfg->iface.iff.dev) - 1] = '\0';
	} else if (!strcmp(name, "mtu")) {
		cfg->iface.mtu = (uint16_t)strtoul(val, NULL, 10);
		cfg->iface.iff.ipv4_mtu = cfg->iface.mtu;
	} else if (!strcmp(name, "ipv4")) {
		strncpy2(cfg->iface.iff.ipv4, val, sizeof(cfg->iface.iff.ipv4));
		cfg->iface.iff.ipv4[sizeof(cfg->iface.iff.ipv4) - 1] = '\0';
	} else if (!strcmp(name, "ipv4_netmask")) {
		strncpy2(cfg->iface.iff.ipv4_netmask, val, sizeof(cfg->iface.iff.ipv4_netmask));
		cfg->iface.iff.ipv4_netmask[sizeof(cfg->iface.iff.ipv4_netmask) - 1] = '\0';
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d", name,
			"iface", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


/*
 * If success, returns 1.
 * If failure, returns 0.
 */
static int server_cfg_parser(void *user, const char *section, const char *name,
			     const char *val, int lineno)
{
	struct cfg_parse_ctx *ctx = (struct cfg_parse_ctx *)user;
	struct srv_cfg *cfg = ctx->cfg;

	if (!strcmp(section, "sys")) {
		return cfg_parse_section_sys(ctx, name, val, lineno);
	} else if (!strcmp(section, "socket")) {
		return cfg_parse_section_socket(ctx, name, val, lineno);
	} else if (!strcmp(section, "iface")) {
		return cfg_parse_section_iface(ctx, name, val, lineno);
	}

	pr_err("Unknown section \"%s\" in at %s:%d", section, cfg->sys.cfg_file,
		lineno);
	return 0;
}


static __cold int parse_cfg_file(const char *cfg_file, struct srv_cfg *cfg)
{
	int ret;
	FILE *handle;
	struct cfg_parse_ctx ctx;

	ctx.cfg = cfg;

	if (!cfg_file)
		return 0;

	handle = fopen(cfg_file, "rb");
	if (!handle) {
		ret = errno;
		pr_err("Cannot open config file \"%s\": " PRERF, cfg_file,
			PREAR(ret));
		return -ret;
	}

	ret = ini_parse_file(handle, server_cfg_parser, &ctx);
	if (ret) {
		pr_err("Failed to parse config file \"%s\"", cfg_file);
		ret = -EINVAL;
	}

	fclose(handle);
	return ret;
}


__cold int run_server(int argc, char *argv[])
{
	int ret;
	struct srv_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));

	set_default_config(&cfg);
	ret = parse_argv(argc, argv, &cfg);
	if (ret)
		return -ret;

	ret = parse_cfg_file(cfg.sys.cfg_file, &cfg);
	if (ret) {
		if (!(ret == -ENOENT && !strcmp(cfg.sys.cfg_file, d_srv_cfg_file)))
			return -ret;
	}


#ifndef NDEBUG
	dump_server_cfg(&cfg);
#endif

	data_dir = cfg.sys.data_dir;
	switch (cfg.sock.type) {
	case SOCK_UDP:
		return -teavpn2_server_udp_run(&cfg);
	case SOCK_TCP:
	default:
		return ESOCKTNOSUPPORT;
	}
}

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

/* TODO: Write my own getopt function. */

static const struct option long_options[] = {
	{"help",        no_argument,       0, 'h'},
	{"version",     no_argument,       0, 'V'},
	{"verbose",     optional_argument, 0, 'v'},

	{"config",      required_argument, 0, 'c'},
	{"data-dir",    required_argument, 0, 'd'},
	{"thread",      required_argument, 0, 't'},

	{"sock-type",   required_argument, 0, 's'},
	{"bind-addr",   required_argument, 0, 'H'},
	{"bind-port",   required_argument, 0, 'P'},
	{"backlog",     required_argument, 0, 'B'},
	{"encrypt",     no_argument,       0, 'E'},

	{"dev",         required_argument, 0, 'D'},

	{0, 0, 0, 0}
};
static const char short_opt[] = "hVv::c:d:t:s:H:P:B:ED:";


static void show_help(void)
{
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
	PR_CFG(cfg->sock.use_encryption, "%hhu");
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


static int parse_argv(int argc, char *argv[], struct srv_cfg *cfg)
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
		case 'h':
			show_help();
			exit(0);
		case 'V':
			show_version();
			exit(0);
		case 'v': {
			uint8_t level = optarg ? (uint8_t)atoi(optarg) : 6u;
			set_notice_level(level);
			sys->verbose_level = level;
			break;
		}


		/*
		 * Sys config
		 */
		case 'c':
			sys->cfg_file = optarg;
			break;
		case 'd':
			strncpy2(sys->data_dir, optarg, sizeof(sys->data_dir));
			break;
		case 't': {
			int tmp = atoi(optarg);
			if (tmp <= 0) {
				pr_err("Thread num argument must be greater than 0");
				return -EINVAL;
			}
			sys->thread_num = (uint8_t)tmp;
			break;
		}


		/*
		 * Sock config
		 */
		case 's': {
			char tmp[5], *p = tmp;

			strncpy2(tmp, optarg, sizeof(tmp));
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
			strncpy2(sock->bind_addr, optarg, sizeof(sock->bind_addr));
			break;
		case 'P':
			sock->bind_port = (uint16_t)atoi(optarg);
			break;
		case 'E':
			sock->use_encryption = atoi(optarg) ? true : false;
			break;

		/*
		 * Iface config
		 */
		case 'D':
			strncpy2(iface->dev, optarg, sizeof(iface->dev));
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
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


static int parse_cfg_file(const char *cfg_file, struct srv_cfg *cfg)
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


int run_server(int argc, char *argv[])
{
	int ret;
	struct srv_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));

	ret = parse_argv(argc, argv, &cfg);
	if (ret)
		return -ret;

	ret = parse_cfg_file(cfg.sys.cfg_file, &cfg);
	if (ret)
		return -ret;


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

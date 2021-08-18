// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <ctype.h>
#include <getopt.h>
#include <inih/inih.h>
#include <teavpn2/client/common.h>

/* TODO: Write my own getopt function. */


static const struct option long_options[] = {
	{"help",        no_argument,       0, 'h'},
	{"version",     no_argument,       0, 'V'},
	{"verbose",     optional_argument, 0, 'v'},

	{"config",      required_argument, 0, 'c'},
	{"data-dir",    required_argument, 0, 'd'},
	{"thread",      required_argument, 0, 't'},

	{"sock-type",   required_argument, 0, 's'},
	{"server-addr", required_argument, 0, 'H'},
	{"server-port", required_argument, 0, 'P'},
	{"max-conn",    required_argument, 0, 'C'},
	{"backlog",     required_argument, 0, 'B'},
	{"encrypt",     no_argument,       0, 'E'},

	{"dev",         required_argument, 0, 'D'},

	{0, 0, 0, 0}
};
static const char short_opt[] = "hVv::c:d:t:s:H:P:C:B:E:D:";


static void show_help(void)
{
}


#define PR_CFG(C, FMT) printf("   " #C " = " FMT "\n", C)

static void dump_client_cfg(struct cli_cfg *cfg)
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
	PR_CFG(cfg->sock.server_addr, "%s");
	PR_CFG(cfg->sock.server_port, "%hu");
	PR_CFG(cfg->sock.event_loop, "%s");
	PR_CFG(cfg->sock.max_conn, "%hu");
	PR_CFG(cfg->sock.backlog, "%d");
	putchar('\n');
	PR_CFG(cfg->iface.dev, "%s");
	puts("=============================================");
}


static int parse_argv(int argc, char *argv[], struct cli_cfg *cfg)
{
	int c;
	struct cli_cfg_sys *sys = &cfg->sys;
	struct cli_cfg_sock *sock = &cfg->sock;
	struct cli_cfg_iface *iface = &cfg->iface;

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
			strncpy(sys->data_dir, optarg, sizeof(sys->data_dir));
			sys->data_dir[sizeof(sys->data_dir) - 1] = '\0';
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
			strncpy(sock->server_addr, optarg, sizeof(sock->server_addr));
			sock->server_addr[sizeof(sock->server_addr) - 1] = '\0';
			break;
		case 'P':
			sock->server_port = (uint16_t)atoi(optarg);
			break;
		case 'C':
			sock->max_conn = (uint16_t)atoi(optarg);
			break;
		case 'B':
			sock->backlog = atoi(optarg);
			break;
		case 'E':
			sock->use_encryption = atoi(optarg) ? true : false;
			break;

		/*
		 * Iface config
		 */
		case 'D':
			strncpy(iface->dev, optarg, sizeof(iface->dev));
			iface->dev[sizeof(iface->dev) - 1] = '\0';
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}


struct cfg_parse_ctx {
	struct cli_cfg	*cfg;
};


static int cfg_parse_section_sys(struct cfg_parse_ctx *ctx, const char *name,
				 const char *val, int lineno)
{
	struct cli_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "thread")) {
		cfg->sys.thread_num = (uint8_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "verbose_level")) {
		cfg->sys.verbose_level = (uint8_t)strtoul(val, NULL, 10);
	} else if (!strcmp(name, "data_dir")) {
		strncpy(cfg->sys.data_dir, val, sizeof(cfg->sys.data_dir));
		cfg->sys.data_dir[sizeof(cfg->sys.data_dir) - 1] = '\0';
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d\n", name,
			"sys", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


static int cfg_parse_section_socket(struct cfg_parse_ctx *ctx, const char *name,
				    const char *val, int lineno)
{
	struct cli_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "use_encryption")) {
		cfg->sock.use_encryption = atoi(val) ? true : false;
	} else if (!strcmp(name, "event_loop")) {
		strncpy(cfg->sock.event_loop, val, sizeof(cfg->sock.event_loop));
		cfg->sock.event_loop[sizeof(cfg->sock.event_loop) - 1] = '\0';
	} else if (!strcmp(name, "sock_type")) {
		char tmp[8], *p = tmp;
		strncpy(tmp, val, sizeof(tmp));

		tmp[sizeof(tmp) - 1] = '\0';
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
	} else if (!strcmp(name, "server_addr")) {
		strncpy(cfg->sock.server_addr, val, sizeof(cfg->sock.server_addr));
		cfg->sock.server_addr[sizeof(cfg->sock.server_addr) - 1] = '\0';
	} else if (!strcmp(name, "server_port")) {
		cfg->sock.server_port = (uint16_t)strtoul(val, NULL, 10);
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d\n", name,
			"socket", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


static int cfg_parse_section_iface(struct cfg_parse_ctx *ctx, const char *name,
				   const char *val, int lineno)
{
	struct cli_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "dev")) {
		strncpy(cfg->iface.dev, val, sizeof(cfg->iface.dev));
		cfg->iface.dev[sizeof(cfg->iface.dev) - 1] = '\0';
	} else if (!strcmp(name, "override_default")) {
		cfg->iface.override_default = (bool)strtoul(val, NULL, 10);
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d\n", name,
			"iface", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


static int cfg_parse_section_auth(struct cfg_parse_ctx *ctx, const char *name,
				  const char *val, int lineno)
{
	struct cli_cfg *cfg = ctx->cfg;
	if (!strcmp(name, "username")) {
		strncpy(cfg->auth.username, val, sizeof(cfg->auth.username));
		cfg->auth.username[sizeof(cfg->auth.username) - 1] = '\0';
	} else if (!strcmp(name, "password")) {
		strncpy(cfg->auth.password, val, sizeof(cfg->auth.password));
		cfg->auth.password[sizeof(cfg->auth.password) - 1] = '\0';
	} else {
		pr_err("Unknown name \"%s\" in section \"%s\" at %s:%d\n", name,
			"auth", cfg->sys.cfg_file, lineno);
		return 0;
	}
	return 1;
}


/*
 * If success, returns 1.
 * If failure, returns 0.
 */
static int client_cfg_parser(void *user, const char *section, const char *name,
			     const char *val, int lineno)
{
	struct cfg_parse_ctx *ctx = (struct cfg_parse_ctx *)user;
	struct cli_cfg *cfg = ctx->cfg;

	if (!strcmp(section, "sys")) {
		return cfg_parse_section_sys(ctx, name, val, lineno);
	} else if (!strcmp(section, "socket")) {
		return cfg_parse_section_socket(ctx, name, val, lineno);
	} else if (!strcmp(section, "iface")) {
		return cfg_parse_section_iface(ctx, name, val, lineno);
	} else if (!strcmp(section, "auth")) {
		return cfg_parse_section_auth(ctx, name, val, lineno);
	}

	pr_err("Unknown section \"%s\" in at %s:%d", section, cfg->sys.cfg_file,
		lineno);
	return 0;
}


static int parse_cfg_file(const char *cfg_file, struct cli_cfg *cfg)
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

	ret = ini_parse_file(handle, client_cfg_parser, &ctx);
	if (ret) {
		pr_err("Failed to parse config file \"%s\"", cfg_file);
		ret = -EINVAL;
	}

	fclose(handle);
	return ret;
}


/*
 * This function should return a positive integer or zero.
 *
 * The parser returns -errno value, hence we negate the return
 * value inside this function.
 */
int run_client(int argc, char *argv[])
{
	int ret;
	struct cli_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));

	pr_debug("Parsing argv...");
	ret = parse_argv(argc, argv, &cfg);
	if (ret)
		return -ret;

	ret = parse_cfg_file(cfg.sys.cfg_file, &cfg);
	if (ret)
		return -ret;

	dump_client_cfg(&cfg);


	return 0;
}

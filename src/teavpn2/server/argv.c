// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/server/argv.c
 *
 *  Argument parser for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <teavpn2/lib/arena.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/common.h>


struct parse_struct {
	char		*app;
	struct srv_cfg  *cfg;
};

/* ---------------------- Default configuration values ---------------------- */
#ifdef SERVER_DEFAULT_CFG_FILE
char d_srv_cfg_file[] = SERVER_DEFAULT_CFG_FILE;
#else
char d_srv_cfg_file[] = "/etc/teavpn2/server.ini";
#endif

/* Default config for virtual network interface */
uint16_t d_srv_mtu = 1500u;
char d_srv_dev[] = "teavpn2";
char d_srv_ipv4[] = "10.7.7.1";
char d_srv_ipv4_netmask[] = "255.255.255.0";

/* Default config for socket */
sock_type d_srv_sock_type = SOCK_TCP;
char d_srv_bind_addr[] = "0.0.0.0";
uint16_t d_srv_bind_port = 55555u;
uint16_t d_srv_max_conn = 10;
int d_srv_backlog = 5;
/* -------------------------------------------------------------------------- */


static __always_inline void init_default_cfg(struct srv_cfg *cfg)
{
	struct srv_sock_cfg *sock = &cfg->sock;
	struct srv_iface_cfg *iface = &cfg->iface;

	cfg->cfg_file = d_srv_cfg_file;
	cfg->data_dir = NULL;

	/* Virtual network interface config */
	iface->mtu = d_srv_mtu;
	iface->dev = d_srv_dev;
	iface->ipv4 = d_srv_ipv4;
	iface->ipv4_netmask = d_srv_ipv4_netmask;

	/* Socket config */
	sock->type = d_srv_sock_type;
	sock->bind_addr = d_srv_bind_addr;
	sock->bind_port = d_srv_bind_port;
	sock->max_conn = d_srv_max_conn;
	sock->backlog = d_srv_backlog;
}



static const struct option long_opt[] = {
	{"help",          no_argument,       0, 'h'},
	{"version",       no_argument,       0, 'v'},

	/* Config file and data dir */
	{"config",        required_argument, 0, 'c'},
	{"data-dir",      required_argument, 0, 'D'},

	/* Virtual network interface options */
	{"mtu",           required_argument, 0, 'm'},
	{"dev",           required_argument, 0, 'd'},
	{"ipv4",          required_argument, 0, '4'},
	{"ipv4-netmask",  required_argument, 0, 'N'},
#ifdef TEAVPN_IPV6_SUPPORT
	{"ipv6",          required_argument, 0, '6'},
	{"ipv6-netmask",  required_argument, 0, 'M'},
#endif

	/* Socket options */
	{"sock-type",     required_argument, 0, 's'},
	{"bind-addr",     required_argument, 0, 'H'},
	{"bind-port",     required_argument, 0, 'P'},
	{"max-conn",      required_argument, 0, 'k'},
	{"backlog",       required_argument, 0, 'B'},

	{0, 0, 0, 0}
};

static const char short_opt[] =
	"hvc:D:m:d:4:N:"
#ifdef TEAVPN_IPV6_SUPPORT
	"6:M:"
#endif
	"s:H:P:k:B:";

static __always_inline int getopt_handler(int argc, char *argv[],
					  struct parse_struct *ctx)
{
	int c;
	struct srv_cfg *cfg = ctx->cfg;
	struct srv_sock_cfg *sock = &cfg->sock;
	struct srv_iface_cfg *iface = &cfg->iface;

	while (true) {
		int option_index = 0;
		c = getopt_long(argc, argv, short_opt, long_opt, &option_index);
		if (unlikely(c == -1))
			break;

		switch (c) {
		case 'h':
			teavpn_server_show_help(ctx->app);
			goto out_exit;
		case 'v':
			teavpn_print_version();
			goto out_exit;
		case 'c':
			cfg->cfg_file = trunc_str(optarg, 255);
			break;
		case 'D':
			cfg->data_dir = trunc_str(optarg, 255);
			break;
		case 'm':
			iface->mtu = (uint16_t)atoi(trunc_str(optarg, 6));
			break;
		case 'd':
			iface->dev = trunc_str(optarg, 32);
			break;
		case '4':
			iface->ipv4 = trunc_str(optarg, 32);
			break;
		case 'N':
			iface->ipv4_netmask = trunc_str(optarg, 32);
			break;
#ifdef TEAVPN_IPV6_SUPPORT
		case '6':
			iface->ipv6 = trunc_str(optarg, 64);
			break;
		case 'M':
			iface->ipv6_netmask = trunc_str(optarg, 64);
			break;
#endif
		case 's': {
			union {
				char		targ[4];
				uint32_t	int_rep;
			} t;
			t.int_rep = 0;
			sane_strncpy(t.targ, optarg, sizeof(t.targ));
			t.int_rep |= 0x20202020u; /* tolower */
			t.targ[3]  = '\0';
			if (!memcmp(t.targ, "tcp", 4)) {
				sock->type = SOCK_TCP;
			} else
			if (!memcmp(t.targ, "udp", 4)) {
				sock->type = SOCK_UDP;
			} else {
				pr_error("Invalid socket type \"%s\"",
					 optarg);
				return -1;
			}
		}
			break;
		case 'H':
			sock->bind_addr = trunc_str(optarg, 255);
			break;
		case 'P':
			sock->bind_port = (uint16_t)atoi(trunc_str(optarg, 6));
			break;
		case 'k':
			sock->max_conn = (uint16_t)atoi(trunc_str(optarg, 6));
			break;
		case 'B':
			sock->backlog = (int)atoi(trunc_str(optarg, 6));
			break;
		default:
			return -1;
		}
	}
	return 0;
out_exit:
	exit(0);
}


int teavpn_server_argv_parse(int argc, char *argv[], struct srv_cfg *cfg)
{
	struct parse_struct ctx;

	ctx.app = argv[0];
	ctx.cfg = cfg;
	init_default_cfg(cfg);
	if (getopt_handler(argc - 1, argv + 1, &ctx) < 0)
		return -1;

	return 0;
}

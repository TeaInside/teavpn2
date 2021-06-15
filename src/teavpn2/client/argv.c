// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/client/entry.c
 *
 *  Argument parser for TeaVPN2 client
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdlib.h>
#include <bluetea/lib/string.h>
#include <bluetea/lib/getopt.h>
#include <teavpn2/client/common.h>


static __no_return void teavpn2_help_client(const char *app)
{
	printf("Usage: %s client [options]\n\n", app);
	exit(0);
}


static void init_default_cfg_values(struct cli_cfg *cfg)
{
	struct cli_sys_cfg   *sys   = &cfg->sys;
	struct cli_sock_cfg  *sock  = &cfg->sock;
	struct cli_iface_cfg *iface = &cfg->iface;

	sys->cfg_file       = NULL;
	sys->data_dir       = NULL;
	sys->verbose_level  = 5;
	sys->thread         = 1;

	sock->type          = SOCK_TCP;
	sock->server_addr   = NULL;
	sock->server_port   = 55555;

	sane_strncpy(iface->dev, "teavpn2-cli", sizeof(iface->dev));
}


int teavpn2_client_parse_argv(int argc, char *argv[], struct cli_cfg *cfg)
{
	int ret = 0, i = 0;
	static const struct bt_getopt_long long_opt[] = {
		{"help",		NO_VAL,		'h'},
		{"version",		NO_VAL,		'V'},
		{"config",		REQUIRED_VAL,	'c'},
		{"data-dir",		REQUIRED_VAL,	'd'},
		{"verbose",		OPTIONAL_VAL,	'v'},
		{"thread",		OPTIONAL_VAL,	't'},

		{"sock-type",		REQUIRED_VAL,	's'},
		{"server-addr",		REQUIRED_VAL,	'H'},
		{"server-port",		REQUIRED_VAL,	'P'},
		{"disable-encryption",	NO_VAL,		'N'},

		{"dev",			REQUIRED_VAL,	'D'},

		GETOPT_LONG_STRUCT_END
	};
	static const char short_opt[] = "hVc:d:v::t::s:H:P:ND:";
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};

	init_default_cfg_values(cfg);

	while (true) {
		int c = bt_getopt(&wr);
		char *retval = NULL;

		if (c == BT_GETOPT_END)
			break;

		/*
		 * Program arguments:
		 * ./teavpn2 server [options]
		 *
		 * We skip `./teavpn2` and `server`
		 */
		if (i == 0 || i == 1)
			goto end_while;

		if (c == BT_GETOPT_UNKNOWN_OPT) {
			printf("Unknown option: %s\n", wr.argv[wr.cur_idx - 1]);
			ret = -EINVAL;
			break;
		}

		if (c == BT_GETOPT_MISSING_VAL) {
			printf("Option \"%s\" requires a value\n",
			       wr.argv[wr.cur_idx - 1]);
			ret = -EINVAL;
			break;
		}

		if (c < 0) {
			printf("bt_getopt error: %d\n", c);
			ret = -EINVAL;
			break;
		}

		retval = wr.retval;

		switch (c) {
		case 'h':
			teavpn2_help_client(argv[0]);
		case 'V':
			printf("TeaVPN2 " TEAVPN2_VERSION "\n");
			exit(0);
		case 'c':
			cfg->sys.cfg_file = trunc_str(retval, 255);
			break;
		case 'd':
			cfg->sys.data_dir = trunc_str(retval, 255);
			break;
		case 'v':
			/* TODO: Handle verbose level */
			break;
		case 't': {
			char cc = *retval;
			if (cc < '0' || cc > '9') {
				printf("Thread argument must be a number, "
				       "non numeric was value given: \"%s\"\n",
				       retval);
				ret = -EINVAL;
				goto out;
			}

			cfg->sys.thread = (uint16_t)atoi(retval);
			break;
		}
		case 's': {
			union {
				char		buf[4];
				uint32_t	do_or;
			} b;

			b.do_or = 0ul;
			sane_strncpy(b.buf, retval, sizeof(b.buf));
			b.do_or |= 0x20202020ul;
			b.buf[sizeof(b.buf) - 1] = '\0';

			if (!strncmp(b.buf, "tcp", 3)) {
				cfg->sock.type = SOCK_TCP;
			} else
			if (!strncmp(b.buf, "udp", 3)) {
				cfg->sock.type = SOCK_UDP;
			} else {
				printf("Invalid socket type: \"%s\"\n", retval);
				ret = -EINVAL;
				goto out;
			}

			break;
		}
		case 'H':
			cfg->sock.server_addr = trunc_str(retval, 255);
			break;
		case 'P':
			cfg->sock.server_port = (uint16_t)atoi(retval);
			break;
		case 'N':
			cfg->sock.use_encrypt = false;
			break;
		case 'D':
			sane_strncpy(cfg->iface.dev, retval,
				     sizeof(cfg->iface.dev));
			break;
		default:
			printf("Invalid option: '%c'\n", c);
			ret = -EINVAL;
			goto out;
		}
	end_while:
		i++;
	}

out:
	return ret;
}

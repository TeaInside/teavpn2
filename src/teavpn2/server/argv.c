// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/entry.c
 *
 *  Argument parser for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdlib.h>
#include <bluetea/lib/string.h>
#include <bluetea/lib/getopt.h>
#include <teavpn2/server/common.h>

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#define __no_return __attribute__((noreturn))

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

static __no_return void teavpn2_help_server(const char *app)
{
	printf("Usage: %s server [options]\n\n", app);
	exit(0);
}


int teavpn2_argv_parse(int argc, char *argv[], struct srv_cfg *cfg)
{
	int ret = 0, i = 0;
	static const struct bt_getopt_long long_opt[] = {
		{"help",		NO_VAL,		'h'},
		{"version",		NO_VAL,		'V'},
		{"data-dir",		REQUIRED_VAL,	'd'},
		{"verbose",		OPTIONAL_VAL,	'v'},
		{"thread",		REQUIRED_VAL,	't'},

		{"sock-type",		REQUIRED_VAL,	's'},
		{"bind-addr",		REQUIRED_VAL,	'H'},
		{"bind-port",		REQUIRED_VAL,	'P'},
		{"max-conn",		REQUIRED_VAL,	'C'},
		{"backlog",		REQUIRED_VAL,	'B'},
		{"ssl-cert",		REQUIRED_VAL,	'S'},
		{"ssl-priv",		REQUIRED_VAL,	'p'},
		{"ssl-priv-key",	REQUIRED_VAL,	'p'}, /* Alias */

		{"dev",			REQUIRED_VAL,	'D'},
		{"mtu",			REQUIRED_VAL,	'm'},
		{"ipv4",		REQUIRED_VAL,	'4'},
		{"ipv4-netmask",	REQUIRED_VAL,	'n'},

		GETOPT_LONG_STRUCT_END
	};
	static const char short_opt[] = "hVd:v::t:s:H:P:C:B:S:p:D:m:4:n:";
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};

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

		// printf("c = %d\n", c);

		retval = wr.retval;

		switch (c) {
		case 'h':
			teavpn2_help_server(argv[0]);
		case 'V':
			printf("TeaVPN2 " TEAVPN2_VERSION "\n");
			exit(0);
		case 'd':
			cfg->sys.data_dir = trunc_str(retval, 255);
			break;
		case 'v':
			/* TODO: Handle verbose level */
			break;
		case 't':
			cfg->sys.thread = (uint16_t)atoi(retval);
			break;
		case 's': {
			char buf[4];
			uint32_t tmp = 0;

			memcpy(&tmp, retval, sizeof(tmp));
			tmp |= 0x20202020u;
			memcpy(buf, &tmp, sizeof(buf));
			buf[3] = '\0';

			if (!strncmp(buf, "tcp", 3)) {
				cfg->sock.type = SOCK_TCP;
			} else
			if (!strncmp(buf, "udp", 3)) {
				cfg->sock.type = SOCK_UDP;
			} else {
				printf("Invalid socket type: \"%s\"\n", retval);
				ret = EINVAL;
				goto out;
			}

			break;
		}
		case 'H':
			cfg->sock.bind_addr = trunc_str(retval, 255);
			break;
		case 'P':
			cfg->sock.bind_port = (uint16_t)atoi(retval);
			break;
		case 'C':
			cfg->sock.max_conn = (uint16_t)atoi(retval);
			break;
		case 'B':
			cfg->sock.backlog = atoi(retval);
			break;
		case 'S':
			cfg->sock.ssl_cert = trunc_str(retval, 512);
			break;
		case 'p':
			cfg->sock.ssl_priv_key = trunc_str(retval, 512);
			break;
		case 'D':
			sane_strncpy(cfg->iface.dev, retval,
				     sizeof(cfg->iface.dev));
			break;
		case 'm':
			cfg->iface.mtu = (uint16_t)atoi(retval);
			break;
		case '4':
			sane_strncpy(cfg->iface.ipv4, retval,
				     sizeof(cfg->iface.ipv4));
			break;
		case 'n':
			sane_strncpy(cfg->iface.ipv4_netmask, retval,
				     sizeof(cfg->iface.ipv4_netmask));
			break;
		default:
			printf("Invalid option: '%c'\n", c);
			ret = EINVAL;
			goto out;
		}

	end_while:
		i++;
	}

out:
	return ret;
}

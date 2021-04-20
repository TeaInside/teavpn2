// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/entry.c
 *
 *  Argument parser for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/getopt.h>
#include <teavpn2/server/common.h>


int teavpn2_argv_parse(int argc, char *argv[], struct srv_cfg *cfg)
{
	int ret;
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

		if (c == BT_GETOPT_END)
			break;

		switch (c) {
		case 'h':
			break;
		case 'V':
			break;
		case 'd':
			break;
		case 'v':
			break;
		case 't':
			break;
		case 's':
			break;
		case 'H':
			break;
		case 'P':
			break;
		case 'C':
			break;
		case 'B':
			break;
		case 'S':
			break;
		case 'p':
			break;
		case 'D':
			break;
		case 'm':
			break;
		case '4':
			break;
		case 'n':
			break;
		default:
			break;
		}
	}
}

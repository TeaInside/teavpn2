// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <getopt.h>
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


int run_client(int argc, char *argv[])
{
	struct cli_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	(void)long_options;
	(void)argc;
	(void)argv;
	return 0;
}

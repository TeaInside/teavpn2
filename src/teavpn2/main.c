// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/main.c
 *
 *  Entry point of TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <string.h>
#include <teavpn2/base.h>


static void show_general_help(const char *app)
{
	printf("Usage: %s [client|server] [options]\n\n", app);
	printf("See:\n");
	printf(" [Help]\n");
	printf("   %s server --help\n", app);
	printf("   %s client --help\n", app);
	printf("\n");
	printf(" [Version]\n");
	printf("   %s --version\n", app);

}


int main(int argc, char *argv[])
{
	int ret = 0;
	if (argc == 1)
		goto out_show_help;

	if (!strncmp(argv[1], "server", 6)) {

	} else
	if (!strncmp(argv[1], "client", 6)) {

	} else
	if (!strncmp(argv[1], "--version", 9)) {
		printf("TeaVPN2 " TEAVPN2_VERSION "\n");
	} else {
		printf("Invalid argument: \"%s\"\n", argv[1]);
		ret = EINVAL;
		goto out_show_help;
	}

	goto out;

out_show_help:
	show_general_help(argv[0]);
out:
	return ret;
}

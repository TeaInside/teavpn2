// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <teavpn2/common.h>


static void show_general_usage(const char *app)
{
	printf(" Usage: %s [client|server] [options]\n\n", app);
	printf(" See:\n");
	printf("  [Help]\n");
	printf("    %s server --help\n", app);
	printf("    %s client --help\n", app);
	printf("\n");
	printf("  [Version]\n");
	printf("    %s --version\n\n", app);
}


static int run_teavpn2(int argc, char *argv[])
{
	if (!strcmp("server", argv[1]))
		return run_server(argc - 1, argv + 1);

	if (!strcmp("client", argv[1]))
		return run_client(argc - 1, argv + 1);

	printf("Invalid command: %s\n", argv[1]);
	show_general_usage(argv[0]);
	return 1;
}


int main(int argc, char *argv[])
{
	if (setvbuf(stdout, NULL, _IOLBF, 2048))
		printf("Cannot set stdout buffer: %s\n", strerror(errno));

	if (setvbuf(stderr, NULL, _IOLBF, 2048))
		printf("Cannot set stderr buffer: %s\n", strerror(errno));

	if (argc == 1) {
		show_general_usage(argv[0]);
		return 0;
	}

	return run_teavpn2(argc, argv);
}

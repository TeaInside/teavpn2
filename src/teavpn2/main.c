// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <teavpn2/common.h>


static int run_teavpn2(int argc, char const *argv[])
{

}


static int show_general_usage(void)
{
	return 0;
}


int main(int argc, char const *argv[])
{
	if (setvbuf(stdout, NULL, _IOLBF, 2048))
		printf("Cannot set stdout buffer: %s\n", strerror(errno));

	if (setvbuf(stderr, NULL, _IOLBF, 2048))
		printf("Cannot set stderr buffer: %s\n", strerror(errno));

	if (argc == 1)
		return show_general_usage();

	return run_teavpn2(argc, argv);
}

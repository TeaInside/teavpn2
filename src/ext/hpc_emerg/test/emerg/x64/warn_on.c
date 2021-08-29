// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <emerg/emerg.h>


int main(void)
{
	if (emerg_init_handler(EMERG_INIT_ALL)) {
		perror("emerg_init_handler");
		return 1;
	}

	if (WARN_ON(0))
		return 1;

	WARN_ON(1);
	return 0;
}

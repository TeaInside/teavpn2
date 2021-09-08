// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <emerg/emerg.h>


static void *thread_bug_release(void *arg)
{
	(void)arg;
	sleep(3);
	__emerg_release_bug = true;
	return NULL;
}


int main(void)
{
	pthread_t thread;

	if (emerg_init_handler(EMERG_INIT_ALL)) {
		perror("emerg_init_handler");
		return 1;
	}


	if (pthread_create(&thread, NULL, thread_bug_release, NULL)) {
		perror("pthread_create");
		return 1;
	}


	if (pthread_detach(thread)) {
		perror("pthread_detach");
		return 1;
	}

	if (BUG_ON(0))
		return 1;

	BUG_ON(1);
	return 0;
}

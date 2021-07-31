// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/tests/004_mutex/004_mutex.c
 *
 *  Test case for queue library.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <bluetea/bluetest.h>

#define DONT_INLINE_BT_MUTEX
#include <bluetea/lib/mutex.h>


struct basic_mutex_st {
	bool		start;
	struct bt_mutex	lock;
	void		*arg;
};


static void *basic_mutex_test(void *arg)
{
	struct basic_mutex_st *data = arg;
	size_t *num_p = data->arg;
	data->start = true;
	for (size_t i = 0; i < (100000000ull / 10000ull); i++) {
		bt_mutex_lock(&data->lock);
		for (size_t j = 0; j < 10000ull; j++) {
			(*num_p)++;
			__asm__ volatile("":"+r"(data)::"memory");
		}
		bt_mutex_unlock(&data->lock);
	}
	return arg;
}


static __maybe_unused BLUETEST(004_mutex, basic_mutex)
{
	TQ_START;
	size_t num = 0;
	pthread_t tr;
	struct basic_mutex_st data;
	memset(&tr, 0, sizeof(tr)); // Shut the clang up!
	data.arg = &num;
	data.start = false;

	TQ_ASSERT(!bt_mutex_init(&data.lock, NULL));
	TQ_ASSERT(!pthread_create(&tr, NULL, basic_mutex_test, &data));
	TQ_IF_RUN {
		while (!data.start)
			__asm__ volatile("rep;\n\tnop;");

		for (size_t i = 0; i < (100000000ull / 10000ull); i++) {
			bt_mutex_lock(&data.lock);
			for (size_t j = 0; j < 10000ull; j++) {
				num++;
				__asm__ volatile("":"+m"(num)::"memory");
			}
			bt_mutex_unlock(&data.lock);
		}
	}
	TQ_ASSERT(!pthread_join(tr, NULL));
	TQ_ASSERT(num == 100000000ull * 2ull);
	TQ_ASSERT(!bt_mutex_destroy(&data.lock));
	TQ_RETURN;
}


struct basic_cond_st {
	bool		start;
	struct bt_mutex	lock;
	struct bt_cond	cond;
	size_t		cond_var;
	void		*arg;
};


static void *basic_cond_test(void *arg)
{
	struct basic_cond_st *data = arg;

	data->start = true;

	bt_mutex_lock(&data->lock);
	for (size_t i = 1; i <= 1000000; i++) {
		data->cond_var++;
		__asm__ volatile("":"+r"(data)::"memory");
	}
	bt_mutex_unlock(&data->lock);
	bt_cond_signal(&data->cond);


	bt_mutex_lock(&data->lock);
	while (data->cond_var != 2000000)
		bt_cond_wait(&data->cond, &data->lock);

	assert(data->cond_var == 2000000);
	for (size_t i = 1; i <= 1000000; i++) {
		data->cond_var++;
		__asm__ volatile("":"+r"(data)::"memory");
	}
	assert(data->cond_var == 3000000);
	bt_mutex_unlock(&data->lock);

	return arg;
}


static BLUETEST(004_mutex, basic_cond)
{
	TQ_START;
	pthread_t tr;
	struct basic_cond_st data;
	memset(&tr, 0, sizeof(tr));
	memset(&data, 0, sizeof(data));
	TQ_ASSERT(!bt_cond_init(&data.cond, NULL));
	TQ_ASSERT(!bt_mutex_init(&data.lock, NULL));
	TQ_ASSERT(!pthread_create(&tr, NULL, basic_cond_test, &data));
	TQ_IF_RUN {
		int ret;
		while (!data.start)
			__asm__ volatile("rep;\n\tnop;");

		bt_mutex_lock(&data.lock);
		while (data.cond_var != 1000000) {
			ret = bt_cond_wait(&data.cond, &data.lock);
			if (ret) {
				printf("Error: %s:%d %s\n", __FILE__, __LINE__,
				       strerror(ret));
				abort();
			}
		}

		TQ_ASSERT_DYN(data.cond_var == 1000000);
		for (size_t i = 1; i <= 1000000; i++) {
			data.cond_var++;
			__asm__ volatile("":"+m"(data)::"memory");
		}
		TQ_ASSERT_DYN(data.cond_var == 2000000);
		bt_mutex_unlock(&data.lock);
		bt_cond_signal(&data.cond);
	}
	TQ_ASSERT(!pthread_join(tr, NULL));
	TQ_ASSERT(data.cond_var == 3000000);
	TQ_ASSERT(!bt_cond_destroy(&data.cond));
	TQ_ASSERT(!bt_mutex_destroy(&data.lock));
	TQ_RETURN;
}


bluetest_entry_t test_entry[] = {
	FN_BLUETEST(004_mutex, basic_mutex),
	FN_BLUETEST(004_mutex, basic_cond),
	NULL
};

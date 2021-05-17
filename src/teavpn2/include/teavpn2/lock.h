// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/lock.h
 *
 *  Lock header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__LOCK_H
#define TEAVPN2__LOCK_H

#include <stdlib.h>
#include <pthread.h>
#include <bluetea/base.h>

#define TEST_LEAK 1

struct tea_mutex {
	bool			is_init;
	pthread_mutex_t		lock;
#if TEST_LEAK
	void			*__test_leak;
#endif
};


static __always_inline int mutex_init(struct tea_mutex *lock,
				      const pthread_mutexattr_t *mutexattr)
{
	memset(lock, 0, sizeof(*lock));
	lock->is_init = true;
#if TEST_LEAK
	lock->__test_leak = malloc(1);
#endif
	return pthread_mutex_init(&lock->lock, mutexattr);
}


static __always_inline int mutex_lock(struct tea_mutex *lock)
{
	assert(lock->is_init);
	return pthread_mutex_lock(&lock->lock);
}


static __always_inline int mutex_unlock(struct tea_mutex *lock)
{
	assert(lock->is_init);
	return pthread_mutex_unlock(&lock->lock);
}


static __always_inline int mutex_destroy(struct tea_mutex *lock)
{
	if (!lock->is_init)
		return 0;

#if TEST_LEAK
	free(lock->__test_leak);
#endif
	return pthread_mutex_destroy(&lock->lock);
}

#endif /* #ifndef TEAVPN2__LOCK_H */

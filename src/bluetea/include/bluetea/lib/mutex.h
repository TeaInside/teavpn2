// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/include/bluetea/lib/mutex.h
 *
 *  Lock and condition library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */


#ifndef BLUETEA__LIB__MUTEX_H
#define BLUETEA__LIB__MUTEX_H

#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <bluetea/base.h>


#define TEST_LEAK 1
#ifdef DONT_INLINE_BT_MUTEX
#  define MUT_INLINE __maybe_unused __no_inline
#else
#  define MUT_INLINE __always_inline
#endif


struct bt_mutex {
	bool			init;
	pthread_mutex_t		mutex;
#if TEST_LEAK
	void			*__test_leak;
#endif
};


struct bt_cond {
	bool			init;
	pthread_cond_t		cond;
#if TEST_LEAK
	void			*__test_leak;
#endif
};


static MUT_INLINE int bt_mutex_init(struct bt_mutex *lock,
				    const pthread_mutexattr_t *mutexattr)
{
	memset(lock, 0, sizeof(*lock));
	__asm__ volatile("":"+r"(lock)::"memory");

#if TEST_LEAK
	lock->__test_leak = malloc(1);
#endif

	lock->init = true;
	return pthread_mutex_init(&lock->mutex, mutexattr);
}


static MUT_INLINE int bt_mutex_lock(struct bt_mutex *lock)
{
	assert(lock->init);
	return pthread_mutex_lock(&lock->mutex);
}


static MUT_INLINE int bt_mutex_unlock(struct bt_mutex *lock)
{
	assert(lock->init);
	return pthread_mutex_unlock(&lock->mutex);
}


static MUT_INLINE int bt_mutex_destroy(struct bt_mutex *lock)
{
	if (unlikely(!lock->init))
		return 0;

	__asm__ volatile("":"+r"(lock)::"memory");

#if TEST_LEAK
	free(lock->__test_leak);
#endif

	lock->init = false;
	return pthread_mutex_destroy(&lock->mutex);
}


static MUT_INLINE int bt_cond_init(struct bt_cond *cond,
				   const pthread_condattr_t *attr)
{
#if TEST_LEAK
	cond->__test_leak = malloc(1);
#endif
	cond->init = true;
	return pthread_cond_init(&cond->cond, attr);
}


static MUT_INLINE int bt_cond_destroy(struct bt_cond *cond)
{
	int ret = 0;
	if (likely(cond->init)) {
		ret = pthread_cond_destroy(&cond->cond);
		cond->init = false;
	}
#if TEST_LEAK
	free(cond->__test_leak);
#endif
	return ret;
}


static MUT_INLINE int bt_cond_wait(struct bt_cond *__restrict__ cond,
				   struct bt_mutex *__restrict__ lock)
{
	assert(cond->init);
	assert(lock->init);
	return pthread_cond_wait(&cond->cond, &lock->mutex);
}


static MUT_INLINE int bt_cond_signal(struct bt_cond *__restrict__ cond)
{
	assert(cond->init);
	return pthread_cond_signal(&cond->cond);
}


static MUT_INLINE int bt_cond_timedwait(struct bt_cond *__restrict__ cond,
					struct bt_mutex *__restrict__ lock,
					const
					struct timespec *__restrict__ abstime)
{
	assert(cond->init);
	assert(lock->init);
	return pthread_cond_timedwait(&cond->cond, &lock->mutex, abstime);
}


static MUT_INLINE int bt_cond_timedwait_rel(struct bt_cond *__restrict__ cond,
					    struct bt_mutex *__restrict__ lock,
					    uint32_t rel_time)
{
	int ret;
	struct timeval tmvl;
	struct timespec abstime;

	memset(&abstime, 0, sizeof(abstime));
	if (unlikely(gettimeofday(&tmvl, NULL) < 0)) {
		ret = errno;
		printf("Error: gettimeofday(): %s\n", strerror(ret));
		return -ret;
	}

	abstime.tv_sec = tmvl.tv_sec + rel_time;
	return bt_cond_timedwait(cond, lock, &abstime);
}


#endif /* #ifndef BLUETEA__LIB__MUTEX_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__MUTEX_H
#define TEAVPN2__MUTEX_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <teavpn2/common.h>

#define MUTEX_PARANOIA
#define MUTEX_LEAK_ASSERT

struct tmutex {
	pthread_mutex_t		mutex;

#ifdef MUTEX_LEAK_ASSERT
	void			*__leak_assert;
#endif

#ifdef MUTEX_PARANOIA
	_Atomic(bool)		__locked;
	bool			__need_destroy;
#endif
};

#define MUTEX_INITIALIZER			\
{						\
	.mutex = PTHREAD_MUTEX_INITIALIZER	\
}

#define DEFINE_MUTEX(V) struct tmutex V = MUTEX_INITIALIZER


#ifdef MUTEX_PARANOIA
static __always_inline bool lockdep_is_held(struct tmutex *t)
{
	return atomic_load(&t->__locked);
}

static __always_inline void lockdep_set_locked(struct tmutex *t, bool l)
{
	atomic_store(&t->__locked, l);
}

#define lockdep_assert(cond)				\
do {							\
	bool __cond = (cond);				\
	if (likely(__cond))				\
		break;					\
	puts("Lockdep assertion failure: " #cond);	\
	BUG();						\
} while (0)

#define lockdep_assert_held(m)			\
	lockdep_assert(lockdep_is_held(m))

#define lockdep_assert_not_held(m)		\
	lockdep_assert(!lockdep_is_held(m))

#else /* #ifdef MUTEX_PARANOIA */
static __always_inline bool lockdep_is_held(struct tmutex *t)
{
	(void)t;
	return true;
}

static __always_inline void lockdep_set_locked(struct tmutex *t, bool l)
{
	(void)t;
	(void)l;
}

#define lockdep_assert(cond) do { } while (0)
#define lockdep_assert_held(m) do { } while (0)
#define lockdep_assert_not_held(m) do { } while (0)
#endif /* #ifdef MUTEX_PARANOIA */

static __always_inline int mutex_init(struct tmutex *m,
				      const pthread_mutexattr_t *attr)
{
	int ret = pthread_mutex_init(&m->mutex, attr);
	if (unlikely(ret)) {
		pr_err("pthread_mutex_init(): " PRERF, PREAR(ret));
		return -ret;
	}

#ifdef MUTEX_LEAK_ASSERT
	m->__leak_assert = malloc(1);
	BUG_ON(!m->__leak_assert);
#endif

#ifdef MUTEX_PARANOIA
	m->__need_destroy = true;
#endif

	lockdep_set_locked(m, false);
	return 0;
}

static __always_inline int mutex_lock(struct tmutex *m)
	__acquires(m)
{
	int ret = pthread_mutex_lock(&m->mutex);
	lockdep_set_locked(m, true);
	return ret;
}

static __always_inline int mutex_unlock(struct tmutex *m)
	__releases(m)
{
	int ret;

#ifdef MUTEX_PARANOIA
	if (unlikely(!lockdep_is_held(m))) {
		puts("Attempting to unlock non-locked mutex");
		BUG();
	}
#endif
	ret = pthread_mutex_unlock(&m->mutex);
	lockdep_set_locked(m, false);
	return ret;
}

static __always_inline int mutex_trylock(struct tmutex *m)
{
	int ret = pthread_mutex_trylock(&m->mutex);
	if (!ret)
		lockdep_set_locked(m, true);
	return ret;
}

static __always_inline int mutex_destroy(struct tmutex *m)
{
	BUG_ON(!m->__need_destroy);

#ifdef MUTEX_LEAK_ASSERT
	free(m->__leak_assert);
#endif
	lockdep_assert_not_held(m);
	return pthread_mutex_destroy(&m->mutex);
}

#endif /* #ifndef TEAVPN2__MUTEX_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__MUTEX_H
#define TEAVPN2__MUTEX_H

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <teavpn2/common.h>

#define MUTEX_LEAK_ASSERT 0
#define MUTEX_LOCK_ASSERT 0

struct tmutex {
	pthread_mutex_t			mutex;
#if MUTEX_LEAK_ASSERT
	union {
		void			*__leak_assert;
		uint64_t		need_destroy;
	};
#else
	bool				need_destroy;
#endif /* #if MUTEX_LEAK_ASSERT */
};


static __always_inline void mutex_init_mark(struct tmutex *m)
{
#if MUTEX_LEAK_ASSERT
	m->__leak_assert = malloc(1);
	if (unlikely(!m->__leak_assert))
		panic("Cannot initialize __leak_assert for mutex_init_mark");
#else
	m->need_destroy = 1;
#endif /* #if MUTEX_LEAK_ASSERT */
}


static __always_inline int mutex_init(struct tmutex *m,
				      const pthread_mutexattr_t *attr)
{
	int ret;

	memset(m, 0, sizeof(*m));
	ret = pthread_mutex_init(&m->mutex, attr);
	if (unlikely(ret)) {
		ret = errno;
		pr_err("pthread_mutex_init(): " PRERF, PREAR(ret));
		return -ret;
	}
	mutex_init_mark(m);
	return ret;
}


static __always_inline int mutex_lock(struct tmutex *m)
{
	int ret;
	__asm__ volatile("":"+r"(m)::"memory");
	ret = pthread_mutex_lock(&m->mutex);
#if MUTEX_LOCK_ASSERT
	BUG_ON(ret != 0);
#endif
	return ret;
}


static __always_inline int mutex_unlock(struct tmutex *m)
{
	int ret;
	__asm__ volatile("":"+r"(m)::"memory");
	ret = pthread_mutex_unlock(&m->mutex);
#if MUTEX_LOCK_ASSERT
	BUG_ON(ret != 0);
#endif
	return ret;
}


static __always_inline int mutex_trylock(struct tmutex *m)
{
	__asm__ volatile("":"+r"(m)::"memory");
	return pthread_mutex_trylock(&m->mutex);
}


static inline int mutex_destroy(struct tmutex *m)
{
	if (m->need_destroy) {
		int ret = pthread_mutex_destroy(&m->mutex);
		if (unlikely(ret)) {
			pr_err("pthread_mutex_destroy(): " PRERF, PREAR(ret));
			return -ret;
		}

#if MUTEX_LEAK_ASSERT
		free(m->__leak_assert);
		m->__leak_assert = NULL;
#else
		m->need_destroy = 0;
#endif
	}
	return 0;
}

#endif /* #ifndef TEAVPN2__MUTEX_H */

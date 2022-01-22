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

#ifndef __MUTEX_LEAK_ASSERT
#define __MUTEX_LEAK_ASSERT 0
#endif


struct tmutex {
	pthread_mutex_t			mutex;

#if __MUTEX_LEAK_ASSERT
	union {
		void			*__leak_assert;
		uintptr_t		need_destroy;
	};
#else
	bool				need_destroy;
#endif
};


#define MUTEX_INITIALIZER			\
{						\
	.mutex = PTHREAD_MUTEX_INITIALIZER	\
}

#define DEFINE_MUTEX(V) struct tmutex V = MUTEX_INITIALIZER


static __always_inline int mutex_init(struct tmutex *m,
				      const pthread_mutexattr_t *attr)
{
	int ret;

	ret = pthread_mutex_init(&m->mutex, attr);
	if (unlikely(ret)) {
		pr_err("pthread_mutex_init(): " PRERF, PREAR(ret));
		return -ret;
	}

#if __MUTEX_LEAK_ASSERT
	m->__leak_assert = malloc(1);
	BUG_ON(!m->__leak_assert);
#else
	m->need_destroy = true;
#endif

	return ret;
}

static __always_inline int mutex_lock(struct tmutex *m)
{
	return pthread_mutex_lock(&m->mutex);
}

static __always_inline int mutex_unlock(struct tmutex *m)
{
	return pthread_mutex_unlock(&m->mutex);
}

static __always_inline int mutex_trylock(struct tmutex *m)
{
	return pthread_mutex_trylock(&m->mutex);
}

static __always_inline int mutex_destroy(struct tmutex *m)
{
	BUG_ON(!m->need_destroy);

#if __MUTEX_LEAK_ASSERT
	free(m->__leak_assert);
#endif

	return pthread_mutex_destroy(&m->mutex);
}

#endif /* #ifndef TEAVPN2__MUTEX_H */

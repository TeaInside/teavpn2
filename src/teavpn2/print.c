// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <stdarg.h>
#include <teavpn2/print.h>
#include <teavpn2/common.h>

#if defined(__linux__)
	#include <pthread.h>
	static pthread_mutex_t get_time_lock = PTHREAD_MUTEX_INITIALIZER;
	static pthread_mutex_t print_lock    = PTHREAD_MUTEX_INITIALIZER;
#else
	#define pthread_mutex_lock(MUTEX)
	#define pthread_mutex_unlock(MUTEX)
	#define pthread_mutex_trylock(MUTEX)
#endif

uint8_t __notice_level = DEFAULT_NOTICE_LEVEL;

static __always_inline char *get_time(char *buf)
	__must_hold(&print_lock)
{
	size_t len;
	char *time_chr;
	time_t rawtime;
	struct tm *timeinfo;

	pthread_mutex_lock(&get_time_lock);
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	time_chr = asctime(timeinfo);
	len = strnlen(time_chr, 32) - 1;
	memcpy(buf, time_chr, len);
	buf[len] = '\0';
	pthread_mutex_unlock(&get_time_lock);
	return buf;
}


#define PR_COPY_BUF(pr, buf, r, vbuf, ul, fmt, vl)			\
do {									\
	r += snprintf(&vbuf[r], ul - r, "[%s] " pr, get_time(buf));	\
	r += vsnprintf(&vbuf[r], ul - r, fmt, vl);			\
	vbuf[r++] = '\n';						\
	vbuf[r] = '\0';							\
} while (0)


#define DEFINE_PR_FUNC(NAME, PR)					\
void __##NAME(const char *fmt, ...)					\
{									\
	int r = 0;							\
	va_list vl;							\
	char buf[32];							\
	char vbuf[2048];						\
	const int ul = (int) sizeof(vbuf) - 4;				\
									\
	va_start(vl, fmt);						\
	pthread_mutex_lock(&print_lock);				\
	PR_COPY_BUF(PR, buf, r, vbuf, ul, fmt, vl);			\
	r = (int) fwrite(vbuf, sizeof(char), (size_t) r, stdout);	\
	pthread_mutex_unlock(&print_lock);				\
	va_end(vl);							\
	(void) r;							\
}


DEFINE_PR_FUNC(pr_notice, "");
DEFINE_PR_FUNC(pr_error, "Error: ");
DEFINE_PR_FUNC(pr_emerg, "Emergency: ");
DEFINE_PR_FUNC(pr_debug, "Debug: ");
DEFINE_PR_FUNC(pr_warn, "Warning: ");


void __panic(const char *file, int lineno, const char *fmt, ...)
{
	va_list vl;
#if defined(__x86_64__)
	__emerg_release_bug = true;
#endif
	pthread_mutex_trylock(&print_lock);
	pthread_mutex_trylock(&get_time_lock);
	puts("=======================================================");
	printf("Emergency: Panic - Not syncing: ");
	va_start(vl, fmt);
	vprintf(fmt, vl);
	va_end(vl);
	putchar('\n');
	printf("Panic at %s:%d\n", file, lineno);
	#define dump_stack()
	/* TODO: Write real dump_stack() */
	dump_stack();
	#undef dump_stack
	puts("=======================================================");
	fflush(stdout);
	abort();
}

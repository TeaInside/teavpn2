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


void __attribute__((format(printf, 1, 2))) __pr_notice(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	va_start(vl, fmt);
	pthread_mutex_lock(&print_lock);
	printf("[%s] ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	pthread_mutex_unlock(&print_lock);
	va_end(vl);
}


void __attribute__((format(printf, 1, 2))) __pr_error(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	va_start(vl, fmt);
	pthread_mutex_lock(&print_lock);
	printf("[%s] Error: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	pthread_mutex_unlock(&print_lock);
	va_end(vl);
}


void __attribute__((format(printf, 1, 2)))__pr_emerg(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	va_start(vl, fmt);
	pthread_mutex_lock(&print_lock);
	printf("[%s] Emergency: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	pthread_mutex_unlock(&print_lock);
	va_end(vl);
}


void __attribute__((format(printf, 1, 2))) __pr_debug(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	va_start(vl, fmt);
	pthread_mutex_lock(&print_lock);
	printf("[%s] Debug: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	pthread_mutex_unlock(&print_lock);
	va_end(vl);
}


void __attribute__((format(printf, 1, 2))) __pr_warn(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	va_start(vl, fmt);
	pthread_mutex_lock(&print_lock);
	printf("[%s] Warning: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	pthread_mutex_unlock(&print_lock);
	va_end(vl);
}


void __attribute__((format(printf, 3, 4)))
__panic(const char *file, int lineno, const char *fmt, ...)
{
	va_list vl;
	__emerg_release_bug = true;
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

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/print.c
 *
 *  Printing functions
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <teavpn2/print.h>


#if defined(__linux__)
#  include <pthread.h>
static pthread_mutex_t get_time_mt  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pr_error_mt  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pr_emerg_mt  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pr_debug_mt  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pr_notice_mt = PTHREAD_MUTEX_INITIALIZER;
#else
#  define pthread_mutex_lock
#  define pthread_mutex_unlock
#endif

#ifdef DEFAULT_NOTICE_LEVEL
uint8_t __notice_level = DEFAULT_NOTICE_LEVEL;
#else
uint8_t __notice_level = 3;
#endif


void teavpn_print_version(void)
{
	puts("TeaVPN2 " TEAVPN2_VERSION);
}


static __always_inline char *get_time(char *buf)
{
	size_t len;
	char *time_chr;
	time_t rawtime;
	struct tm *timeinfo;

	/*
	 * These `time` functions are not thread-safe, hence
	 * we need mutex here.
	 */
	pthread_mutex_lock(&get_time_mt);
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	time_chr = asctime(timeinfo);
	len = strnlen(time_chr, 32) - 1;
	memcpy(buf, time_chr, len);
	buf[len] = '\0';
	pthread_mutex_unlock(&get_time_mt);

	return buf;
}


void __attribute__((format(printf, 1, 2))) __pr_error(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_error_mt);
	va_start(vl, fmt);
	printf("[%s] Error: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	va_end(vl);
	pthread_mutex_unlock(&pr_error_mt);
}


void __attribute__((format(printf, 1, 2))) __pr_emerg(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_emerg_mt);
	va_start(vl, fmt);
	printf("[%s] Emergency: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	va_end(vl);
	pthread_mutex_unlock(&pr_emerg_mt);
}


void __attribute__((format(printf, 1, 2))) __pr_debug(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_debug_mt);
	va_start(vl, fmt);
	printf("[%s] Debug: ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	va_end(vl);
	pthread_mutex_unlock(&pr_debug_mt);
}


void __attribute__((format(printf, 1, 2))) __pr_notice(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_notice_mt);
	va_start(vl, fmt);
	printf("[%s] ", get_time(buf));
	vprintf(fmt, vl);
	putchar('\n');
	va_end(vl);
	pthread_mutex_unlock(&pr_notice_mt);
}

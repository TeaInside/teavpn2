
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <teavpn2/global/helpers/debug.h>


#if defined(__linux__)
# include <pthread.h>
pthread_mutex_t get_time_mt  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pr_error_mt  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pr_notice_mt = PTHREAD_MUTEX_INITIALIZER;
#else
#define pthread_mutex_lock(MUT) /* Do nothing */
#define pthread_mutex_unlock(MUT) /* Do nothing */
#endif

int8_t __notice_level = 5;


inline static char *get_time(char *buf)
{
	size_t len;
	char   *time_chr;
	time_t rawtime;
	struct tm *timeinfo;

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


void __pr_error(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_error_mt);

	va_start(vl, fmt);
	printf("[%s] Error: ", get_time(buf));
	vprintf(fmt, vl);
	va_end(vl);
	putchar(10);

	pthread_mutex_unlock(&pr_error_mt);
}

void __pr_notice(const char *fmt, ...)
{
	va_list vl;
	char buf[32];

	pthread_mutex_lock(&pr_notice_mt);

	va_start(vl, fmt);
	printf("[%s] ", get_time(buf));
	vprintf(fmt, vl);
	va_end(vl);
	putchar(10);

	pthread_mutex_unlock(&pr_notice_mt);
}

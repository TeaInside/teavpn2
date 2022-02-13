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
	static __maybe_unused pthread_mutex_t gui_buf_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
	#define pthread_mutex_lock(MUTEX)
	#define pthread_mutex_unlock(MUTEX)
	#define pthread_mutex_trylock(MUTEX)
#endif

uint8_t __notice_level = DEFAULT_NOTICE_LEVEL;


#ifdef CONFIG_GUI

static char *g_gui_buf = NULL;
static size_t g_gui_buf_len = 0;
static size_t g_gui_buf_maxlen = 0;

int gui_pr_buffer_init(size_t len)
{
	pthread_mutex_lock(&gui_buf_mutex);
	g_gui_buf = al64_malloc(len);
	if (!g_gui_buf) {
		pthread_mutex_unlock(&gui_buf_mutex);
		return -ENOMEM;
	}

	g_gui_buf_len = 0;
	g_gui_buf_maxlen = len;
	pthread_mutex_unlock(&gui_buf_mutex);
	return 0;
}

size_t gui_pr_consume_buffer(char *buffer, size_t maxlen)
{
	size_t cpylen;

	if (unlikely(!maxlen))
		return 0;

	pthread_mutex_lock(&gui_buf_mutex);
	if (maxlen < g_gui_buf_len) {
		size_t unconsumed_pos = maxlen;
		size_t memmove_len = g_gui_buf_len - unconsumed_pos;

		cpylen = maxlen;
		memcpy(buffer, g_gui_buf, cpylen);
		memmove(g_gui_buf, &g_gui_buf[unconsumed_pos], memmove_len);
		g_gui_buf_len -= cpylen;
	} else {
		cpylen = g_gui_buf_len;
		if (cpylen > 0) {
			memcpy(buffer, g_gui_buf, cpylen);
			g_gui_buf_len = 0;
		}
	}
	pthread_mutex_unlock(&gui_buf_mutex);
	return cpylen;
}

size_t gui_pr_queue_buffer(const char *buffer, size_t len)
{
	size_t cpylen = 0;
	size_t remaining_size;

	pthread_mutex_lock(&gui_buf_mutex);
	remaining_size = g_gui_buf_maxlen - g_gui_buf_len;
	if (likely(remaining_size > 0)) {
		cpylen = len < remaining_size ? len : remaining_size;
		memcpy(&g_gui_buf[g_gui_buf_len], buffer, cpylen);
		g_gui_buf_len += cpylen;
	}
	pthread_mutex_unlock(&gui_buf_mutex);
	return cpylen;
}
#endif /* #ifdef CONFIG_GUI */

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
	gui_pr_queue_buffer(vbuf, (size_t) r);				\
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
#if defined(CONFIG_HPC_EMERGENCY)
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

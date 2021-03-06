
#ifndef __TEAVPN2__DEBUG_H
#define __TEAVPN2__DEBUG_H

#include <stdint.h>

extern int8_t __notice_level;

void __pr_error(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void __pr_notice(const char *fmt, ...)
	 __attribute__((format(printf, 1, 2)));

#ifndef NOTICE_STATIC_LEVEL
#define NOTICE_STATIC_LEVEL (20)
#endif

#ifndef NOTICE_ALWAYS_EXEC
#define NOTICE_ALWAYS_EXEC  (0)
#endif

#define pr_error  __pr_error
#define pr_debug  __pr_debug
#define pr_notice __pr_notice
#define prl_notice(LEVEL, ...) 					\
	do {							\
		if (NOTICE_ALWAYS_EXEC) {			\
			pr_notice(__VA_ARGS__);			\
		} else						\
		if ((NOTICE_STATIC_LEVEL >= (LEVEL))		\
			&& (__notice_level >= (LEVEL))) {	\
			pr_notice(__VA_ARGS__);			\
		}						\
	} while (0)

#endif /* #ifndef __TEAVPN2__DEBUG_H */

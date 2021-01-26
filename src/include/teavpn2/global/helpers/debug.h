

#ifndef __TEAVPN2__GLOBAL__HELPERS__DEBUG_H
#define __TEAVPN2__GLOBAL__HELPERS__DEBUG_H

#include <stdint.h>

extern uint8_t __notice_level;

void __pr_error(const char *fmt, ...);
void __pr_notice(const char *fmt, ...);

#define NOTICE_STATIC_LEVEL (10u)

#define pr_error  __pr_error
#define pr_debug  __pr_debug
#define pr_notice __pr_notice
#define prl_notice(LEVEL, ...) 					\
	do {							\
		if ((NOTICE_STATIC_LEVEL >= (LEVEL))		\
			&& (__notice_level >= (LEVEL))) {	\
			pr_notice(__VA_ARGS__);			\
		}						\
	} while (0)

#endif /* #ifndef __TEAVPN2__GLOBAL__HELPERS__DEBUG_H */

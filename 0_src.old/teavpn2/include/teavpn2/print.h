// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/include/teavpn2/print.h
 *
 *  Printing header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__PRINT_H
#define TEAVPN2__PRINT_H

#include <stdlib.h>

extern uint8_t __notice_level;

extern void __attribute__((format(printf, 1, 2)))
__pr_notice(const char *fmt, ...);


extern void __attribute__((format(printf, 1, 2)))
__pr_error(const char *fmt, ...);


extern void __attribute__((format(printf, 1, 2)))
__pr_emerg(const char *fmt, ...);


extern void __attribute__((format(printf, 1, 2)))
__pr_debug(const char *fmt, ...);


extern void __attribute__((format(printf, 3, 4))) __attribute__((noreturn))
__panic(const char *file, int lineno, const char *fmt, ...);


#ifndef NOTICE_ALWAYS_EXEC
#  define NOTICE_ALWAYS_EXEC 0
#endif

#ifndef NOTICE_MAX_LEVEL
#  define NOTICE_MAX_LEVEL 6
#endif

#ifndef NOTICE_DEFAULT_LEVEL
#  define NOTICE_DEFAULT_LEVEL NOTICE_MAX_LEVEL
#endif


#define PRERF "(errno=%d) %s"
#define PREAR(NUM) NUM, strerror(NUM)

#define pr_err		__pr_error
#define pr_error	__pr_error
#define pr_notice	__pr_notice
#define pr_emerg	__pr_emerg
#define pr_dbg		__pr_debug
#define panic(...)	__panic(__FILE__, __LINE__, __VA_ARGS__)

#ifdef NDEBUG
/* No debug */
#define pr_debug(...)
#else
/* Yes, do debug */
#define pr_debug	__pr_debug
#endif

#define set_pr_notice_lv(LEVEL)			\
	do {					\
		__notice_level = (LEVEL);	\
	} while (0)


#define prl_notice(LEVEL, ...)						\
do {									\
	const uint8_t ____lvl = (LEVEL);				\
	const bool ____exec = (						\
		(NOTICE_ALWAYS_EXEC) ||					\
		(							\
			((____lvl) <= (NOTICE_MAX_LEVEL)) &&		\
			(						\
				((____lvl) <  (__notice_level)) ||	\
				((____lvl) == (__notice_level))		\
			)						\
		)							\
	);								\
									\
	if (likely(____exec))						\
		pr_notice(__VA_ARGS__);					\
} while (0)


#endif /* #ifndef TEAVPN2__PRINT_H */

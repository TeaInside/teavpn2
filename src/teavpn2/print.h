// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Printing header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__PRINT_H
#define TEAVPN2__PRINT_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <teavpn2/compiler_attributes.h>

extern uint8_t __notice_level;

extern void __printf(1, 2)
__pr_notice(const char *fmt, ...);


extern void __printf(1, 2)
__pr_error(const char *fmt, ...);


extern void __printf(1, 2)
__pr_emerg(const char *fmt, ...);


extern void __printf(1, 2)
__pr_debug(const char *fmt, ...);


extern void __printf(1, 2)
__pr_warn(const char *fmt, ...);


extern void __printf(3, 4) __noreturn
__panic(const char *file, int lineno, const char *fmt, ...);


static inline void set_notice_level(uint8_t level)
{
	__notice_level = level;
}


#define PRERF "(errno=%d) %s"
#define PREAR(NUM) NUM, strerror(NUM)

#define pr_err		__pr_error
#define pr_error	__pr_error
#define pr_notice	__pr_notice
#define pr_emerg	__pr_emerg
#define pr_dbg		__pr_debug
#define pr_warn		__pr_warn

#if defined(__x86_64__)
#define panic(...)					\
do {							\
	__emerg_release_bug = true;			\
	BUG_ON(1);					\
	__panic(__FILE__, __LINE__, __VA_ARGS__);	\
} while (0)
#else
#define panic(...)					\
do {							\
	__panic(__FILE__, __LINE__, __VA_ARGS__);	\
} while (0)
#endif


#ifdef NDEBUG
	/* No debug */
	#define pr_debug(...)
#else
	/* Yes, do debug */
	#define pr_debug	__pr_debug
#endif

#ifndef MAX_NOTICE_LEVEL
	/*
	 * prl_notice(n, "msg") where n is greater than `MAX_NOTICE_LEVEL`
	 * will not be printed even if the `__notice_level` is greater than
	 * n.
	 *
	 * The evaluation of `MAX_NOTICE_LEVEL` could be at compile time!
	 */
	#define MAX_NOTICE_LEVEL 5
#endif

#define DEFAULT_NOTICE_LEVEL 5

#define prl_notice(LEVEL, ...)				\
do {							\
	uint8_t __lc_notice_level = (uint8_t)(LEVEL);	\
	if (__lc_notice_level > (MAX_NOTICE_LEVEL))	\
		break;					\
	if (__lc_notice_level > __notice_level)		\
		break;					\
	pr_notice(__VA_ARGS__);				\
} while (0)

#endif /* #ifndef TEAVPN2__PRINT_H */

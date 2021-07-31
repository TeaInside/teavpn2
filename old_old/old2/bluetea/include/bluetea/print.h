// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/print.h
 *
 *  Printing header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__PRINT_H
#define BLUETEA__PRINT_H

#include <string.h>
#include <stdint.h>
#include <bluetea/base.h>


extern uint8_t __notice_level;


void __attribute__((format(printf, 1, 2)))
__pr_notice(const char *fmt, ...);


void __attribute__((format(printf, 1, 2)))
__pr_error(const char *fmt, ...);


void __attribute__((format(printf, 1, 2)))
__pr_emerg(const char *fmt, ...);


#define PRERF "(errno=%d) %s"
#define PREAR(NUM) NUM, strerror(NUM)


#ifndef NOTICE_ALWAYS_EXEC
#  define NOTICE_ALWAYS_EXEC 0
#endif

#ifndef NOTICE_MAX_LEVEL
#  define NOTICE_MAX_LEVEL 6
#endif

#ifndef NOTICE_DEFAULT_LEVEL
#  define NOTICE_DEFAULT_LEVEL NOTICE_MAX_LEVEL
#endif


#define pr_error  __pr_error
#define pr_err    __pr_error
#define pr_emerg  __pr_emerg
#define pr_debug  __pr_debug
#define pr_dbg    __pr_debug
#define pr_notice __pr_notice


#define panic(...)		\
do {				\
	pr_emerg("Panic!");	\
	pr_emerg(__VA_ARGS__);	\
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

void gwbot_print_version(void);

#endif /* #ifndef BLUETEA__PRINT_H */

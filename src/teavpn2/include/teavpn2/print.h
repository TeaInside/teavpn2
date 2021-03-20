// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/print.h
 *
 *  Print header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__PRINT_H
#define TEAVPN2__PRINT_H

#include <string.h>
#include <stdint.h>


extern uint8_t __notice_level;

void __pr_error(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void __pr_emerg(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void __pr_debug(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void __pr_notice(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

void __pr_notice_nm(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

#define PRERF "(errno=%d) %s"
#define PREAR(NUM) NUM, strerror(NUM)

#ifndef NOTICE_ALWAYS_EXEC
#  define NOTICE_ALWAYS_EXEC 0
#endif

#ifndef NOTICE_MAX_LEVEL
#  define NOTICE_MAX_LEVEL 6
#endif

#ifndef NOTICE_LEVEL_DEFAULT
#  define NOTICE_LEVEL_DEFAULT NOTICE_MAX_LEVEL
#endif

#define pr_error  __pr_error
#define pr_err    __pr_error

#define pr_emerg  __pr_emerg

#define pr_debug  __pr_debug
#define pr_dbg    __pr_debug

#define pr_notice __pr_notice
#define pr_notice_nm __pr_notice_nm

#define panic(...)					\
do {							\
	pr_emerg("Panic: Not syncing!");		\
	pr_emerg(__VA_ARGS__);				\
} while (0)


#define prl_notice(LEVEL, ...)					\
do {								\
	bool __execute = (					\
		(NOTICE_ALWAYS_EXEC) ||				\
		(						\
			((LEVEL) <= (NOTICE_MAX_LEVEL)) &&	\
			(					\
				(LEVEL) <  (__notice_level) ||	\
				(LEVEL) == (__notice_level)	\
			)					\
		)						\
	);							\
	if (likely(__execute))					\
		pr_notice(__VA_ARGS__);				\
} while (0)



#include <teavpn2/base.h>

#endif /* #ifndef TEAVPN2__PRINT_H */

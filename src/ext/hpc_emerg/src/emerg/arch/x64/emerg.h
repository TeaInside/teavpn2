// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#ifndef IN_THE_MAIN_EMERG_H
#error "This header must only be included from emerg/emerg.h"
#endif

#ifndef EMERG__SRC__X64__EMERG_H
#define EMERG__SRC__X64__EMERG_H

#include <unistd.h>


#define atomic_cmpxchgl(PTR, OLD, NEW) ({			\
	int __ret;						\
	int __old = (OLD);					\
	int __new = (NEW);					\
	volatile int *__ptr = (volatile int *)(PTR);		\
	__asm__ volatile(					\
		"lock\tcmpxchgl %2,%1"				\
		: "=a"(__ret), "+m" (*__ptr)			\
		: "r"(__new), "0"(__old)			\
		: "memory"					\
	);							\
	(__ret);						\
})


#define atomic_read(PTR) ({					\
	int __ret;						\
	volatile int *__ptr = (volatile int *)(PTR);		\
	__asm__ volatile(					\
		"movl %1, %0"					\
		: "=r"(__ret)					\
		: "m"(*__ptr)					\
		: "memory"					\
	);							\
	(__ret);						\
})


#define atomic_set(PTR, VAL) ({					\
	int __val = (VAL);					\
	volatile int *__ptr = (volatile int *)(PTR);		\
	__asm__ volatile(					\
		"movl %1, %0"					\
		: "=m"(*__ptr)					\
		: "r"(__val)					\
		: "memory"					\
	);							\
	(__val);						\
})


#define cpu_relax()			\
do {					\
	__asm__ volatile("rep\n\tnop");	\
} while (0)


/*
 * Despite that some emulators terminate on UD2, we use it.
 */
#define ASM_UD2		".byte 0x0f, 0x0b"
#define INSN_UD2	0x0b0f
#define LEN_UD2		2


#define ASM_EMERG__(INS, TAINT, TYPE)					\
do {									\
	static const struct emerg_entry ____emerg_entry = {		\
		__FILE__,						\
		__func__,						\
		(unsigned int)__LINE__,					\
		TAINT,							\
		(TYPE)							\
	};								\
									\
	__asm__ volatile(						\
		"# ASM_EMERG__\n\t"					\
		INS "\n\t"						\
		"leaq	%0, %%rax"					\
		:							\
		: "m"(____emerg_entry)					\
		:							\
	);								\
} while (0)


#define WARN() ({					\
	ASM_EMERG__(ASM_UD2, 0, EMERG_TYPE_WARN);	\
	(1);						\
})


#define WARN_ONCE() ({						\
	static bool __is_warned = false;			\
	if (unlikely(!__is_warned)) {				\
		__is_warned = true;				\
		ASM_EMERG__(ASM_UD2, 0, EMERG_TYPE_WARN);	\
	}							\
	(1);							\
})


#define WARN_ON(COND) ({			\
	bool __cond = (COND);			\
	if (unlikely(__cond))			\
		WARN();				\
	(unlikely(__cond));			\
})


#define WARN_ON_ONCE(COND) ({			\
	bool __cond = (COND);			\
	static bool __is_warned = false;	\
	if (unlikely(__cond && !__is_warned)) {	\
		__is_warned = true;		\
		WARN();				\
	}					\
	(unlikely(__cond));			\
})


#define BUG() ({					\
	ASM_EMERG__(ASM_UD2, 0, EMERG_TYPE_BUG);	\
	while (!__emerg_release_bug)			\
		usleep(100000);				\
	(1);						\
})


#define BUG_ON(COND) ({				\
	bool __cond = (COND);			\
	if (unlikely(__cond))			\
		BUG();				\
	(unlikely(__cond));			\
})

#endif /* #ifndef EMERG__SRC__X64__EMERG_H */

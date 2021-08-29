// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#ifndef EMERG__SRC__EMERG_H
#define EMERG__SRC__EMERG_H

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#define pr_intr printf
#include "vt_hexdump.h"

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#ifndef __USE_GNU
#  define __USE_GNU
#endif
#include <signal.h>
#include <ucontext.h>
#include <execinfo.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <dlfcn.h>

#ifndef likely
#  define likely(COND) __builtin_expect((bool)(COND), 1)
#endif

#ifndef unlikely
#  define unlikely(COND) __builtin_expect((bool)(COND), 0)
#endif

#ifndef ____stringify
#  define ____stringify(EXPR) #EXPR
#endif

#ifndef __stringify
#  define __stringify(EXPR) ____stringify(EXPR)
#endif

#ifndef __maybe_unused
#  define __maybe_unused __attribute__((unused))
#endif

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

#define IN_THE_MAIN_EMERG_H
#if defined(__x86_64__)
#include "arch/x64/emerg.h"
#else
#error "Arch is not supported yet!"
#endif
#undef IN_THE_MAIN_EMERG_H

#define EMERG_TYPE_BUG		(1u << 0u)
#define EMERG_TYPE_WARN		(1u << 1u)
#define EMERG_TYPE_WARN_ONCE	(1u << 1u)


struct emerg_entry {
	const char		*file;
	const char		*func;
	unsigned int		line;
	unsigned short		flags;
	unsigned short		type;
};


#define EMERG_INIT_BUG		(1u << 0u)
#define EMERG_INIT_WARN		(1u << 1u)
#define EMERG_INIT_SIGSEGV	(1u << 2u)
#define EMERG_INIT_SIGILL	(1u << 3u)
#define EMERG_INIT_SIGFPE	(1u << 4u)
#define EMERG_INIT_ALL		(				\
					EMERG_INIT_BUG |	\
					EMERG_INIT_WARN |	\
					EMERG_INIT_SIGSEGV |	\
					EMERG_INIT_SIGILL |	\
				 	EMERG_INIT_SIGILL	\
				)

typedef bool (*emerg_callback_t)(int sig, siginfo_t *si, ucontext_t *ctx);
extern volatile short __emerg_taint;
extern volatile bool __emerg_release_bug;
extern volatile emerg_callback_t __pre_emerg_print_trace;
extern volatile emerg_callback_t __post_emerg_print_trace;
extern int emerg_init_handler(unsigned bits);
extern void emerg_handler(int sig, siginfo_t *si, void *arg);

#endif /* #ifndef EMERG__SRC__EMERG_H */

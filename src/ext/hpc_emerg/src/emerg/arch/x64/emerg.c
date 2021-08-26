// SPDX-License-Identifier: GPL-2.0-only
/*
 * hpc_emerg for Linux x86-64.
 *
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 *
 * Link: https://github.com/ammarfaizi2/hpc_emerg
 */

#include "../../emerg.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>

#define ALT_STACK_SIZE (1024ul * 1024ul * 8ul)

volatile bool __emerg_release_bug = false;
volatile short __emerg_taint = 0;
volatile emerg_callback_t __pre_emerg_print_trace = NULL;
volatile emerg_callback_t __post_emerg_print_trace = NULL;


/*
 * @vfd is a file descriptor to a temporary file. This is used to validate
 * the memory address by using sys_write().
 *
 * sys_write() returns -EFAULT if the memory address isn't valid, hence we
 * can abuse this situation for virtual address validation before dumping
 * the memory content inside the interrupt handler. We are not allowed to
 * fault inside the interrupt handler.
 *
 * If someone knows better workaround for this, please send me the idea
 * or pull request to the GitHub repository.
 *
 * --
 *  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
static int vfd = -1;
static __maybe_unused const char emerg_file_tmp[] = "/tmp/emerg_file_tmp.tmp";

static unsigned emerg_init_bits = 0;
static pthread_mutex_t emerg_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Regarding @alt_stack:
 *
 * commit 8e5629ffd1dd36d716da9ec24cda2955c43a1865
 * Author: Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Date:   Mon Aug 16 16:38:31 2021 +0700
 *
 *  hpc_emerg: use sigaltstack to handle bad %rsp value
 *   
 *  Aleksey Covacevice wrote:
 *  > I hope you're aware that introspection through signal handlers is not
 *  > reliable. Eg.: if your stack is corrupted somehow, there's little
 *  > chance you can do anything else (since you can't even safely allocate
 *  > local storage).
 *  
 *  Use sigaltstack() to guarantee some stack space even in stack corruption
 *  scenarios.
 *   
 *  Suggested-by: Aleksey Covacevice
 *  Link: https://t.me/assemblybr/37701
 *  Signed-off-by: Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
static char alt_stack[ALT_STACK_SIZE];


/*
 * Validate virtual address (make sure it is readable as well).
 * Returns 1 if the address is valid and readable, otherwise returns 0.
 */
static int is_valid_addr(void *addr, size_t len)
{
	if (unlikely(vfd == -1)) {
		// vfd = open(emerg_file_tmp, O_CREAT | O_WRONLY, 0700);
		vfd = memfd_create("emerg_tmp", MFD_CLOEXEC);
		if (unlikely(vfd < 0))
			return 0;
	}

	return (write(vfd, addr, len) == (ssize_t)len);
}


static int is_emerg_pattern(void *addr)
{
	/*
	 * "\x0f\x0b"		ud2
	 * "\x48\x8d\x05"	lea rax, [rip + ???]
	 */
	return !memcmp("\x0f\x0b\x48\x8d\x05", addr, 5);
}


static void emerg_recover(uintptr_t *regs)
{
	/* Skip the ud2 and lea. */
	regs[REG_RIP] += 5 + 4;
}


static void __print_warn(const char *file, unsigned int line, const char *func)
{
	pr_intr("  WARNING: PID: %d at %s:%u %s\n", getpid(), file, line, func);
}


static void __print_bug(const char *file, unsigned int line, const char *func)
{
	pr_intr("  BUG: PID: %d at %s:%u %s\n", getpid(), file, line, func);
}


static void print_emerg_notice(uintptr_t rip)
{
	int32_t rel_offset;
	struct emerg_entry *entry;

	memcpy(&rel_offset, (void *)(rip + 5), sizeof(rel_offset));
	if (rel_offset > 0) {
		rip += 5 + 4 + (uintptr_t)rel_offset;
	} else {
		rel_offset *= -1;
		rip += 5 + 4;
		rip -= (uintptr_t)rel_offset;
	}

	entry = (struct emerg_entry *)rip;
	switch (entry->type) {
	case EMERG_TYPE_BUG:
		__print_bug(entry->file, entry->line, entry->func);
		break;
	case EMERG_TYPE_WARN:
		__print_warn(entry->file, entry->line, entry->func);
		break;
	}

	/*
	 * TODO: Dump taint list when the process is tainted.
	 */
	pr_intr("  %s: %d; Compiler: " __VERSION__ "\n",
		__emerg_taint ? "Tainted" : "Not tainted", __emerg_taint);
}


static void dump_code(char *buf, void *addr)
{
	unsigned char *end, *start = (unsigned char *)addr;
	start -= 42;
	end = start + 64;
	while (start < end) {
		buf += sprintf(
			buf,
			(start == (unsigned char *)addr) ? "<%02x> " : "%02x ",
			(unsigned)*start
		);
		start++;
	}
}


struct func_addr {
	const char	*name;
	const char	*file;
	unsigned	rip_next;
};


static struct func_addr *func_addr_translate(struct func_addr *buf, void *addr)
{
	Dl_info i;
	if (!dladdr(addr, &i))
		return NULL;

	buf->name = i.dli_sname;
	buf->file = i.dli_fname;
	buf->rip_next = (unsigned)((uintptr_t)addr - (uintptr_t)i.dli_saddr);
	return buf;
}


static void print_backtrace(uintptr_t rip)
{
	int nptrs, i;
	uintptr_t buf[300];

	/*
	 * TODO: create safe backtrace routine.
	 */

	pr_intr("  Call Trace: \n");
	if (!is_valid_addr((void *)rip, 1)) {
		pr_intr("    Not printing call trace due to invalid RIP!\n"
			"    This is very likely not recoverable.\n"
			"    Please use the coredump file for further investigation!\n");
		return;
	}

	nptrs = backtrace((void **)buf, sizeof(buf) / sizeof(buf[0]));
	if (nptrs <= 0) {
		pr_intr("  Unable to retrieve backtrace!\n");
		return;
	}

	for (i = 0; i < nptrs; i++) {
		struct func_addr fx;
		uintptr_t fa = (uintptr_t)buf[i];

		if (!func_addr_translate(&fx, (void *)fa))
			continue;

		pr_intr("  %s[<%#016lx>] %s(%s+%#x)\n",
			(rip == fa) ? "%rip => " : "        ",
			fa,
			fx.file,
			fx.name ? fx.name : "??? 0",
			fx.rip_next
		);
	}
}


static void dump_register(uintptr_t *regs)
{
	char func_buf[512];
	char code_buf[512];
	struct func_addr fx, *fxp;
	unsigned short cgfs[4]; /* unsigned short cs, gs, fs, ss.  */
	memcpy(cgfs, &regs[REG_CSGSFS], sizeof(cgfs));
	void *rip = (void *)regs[REG_RIP];

	if (likely(is_valid_addr((void *)(regs[REG_RIP] - 42), 64))) {
		dump_code(code_buf, rip);
		fxp = func_addr_translate(&fx, rip);
		if (fxp)
			snprintf(func_buf, sizeof(func_buf),
				 "at %s(%s+%#x)",
				 fx.file,
				 fx.name ? fx.name : "??? 0",
				 fx.rip_next);
	} else {
		fxp = NULL;
		func_buf[0] = '\0';
		memcpy(code_buf, "Invalid RIP!", sizeof("Invalid RIP!"));
	}

	pr_intr(
		"  RIP: %016lx %s\n"
		"  Code: %s\n"
		"  RSP: %016lx EFLAGS: %08lx\n"
		"  RAX: %016lx RBX: %016lx RCX: %016lx\n"
		"  RDX: %016lx RSI: %016lx RDI: %016lx\n"
		"  RBP: %016lx R08: %016lx R09: %016lx\n"
		"  R10: %016lx R11: %016lx R12: %016lx\n"
		"  R13: %016lx R14: %016lx R15: %016lx\n"
		"  CS: %04x GS: %04x FS: %04x SS: %04x\n"
		"  CR2: %016lx\n\n",
		regs[REG_RIP], func_buf,
		code_buf,
		regs[REG_RSP], regs[REG_EFL],
		regs[REG_RAX], regs[REG_RBX], regs[REG_RCX],
		regs[REG_RDX], regs[REG_RSI], regs[REG_RDI],
		regs[REG_RBP], regs[REG_R8], regs[REG_R9],
		regs[REG_R10], regs[REG_R11], regs[REG_R12],
		regs[REG_R13], regs[REG_R14], regs[REG_R15],
			/* cs */ cgfs[0],
			/* gs */ cgfs[1],
			/* fs */ cgfs[2],
			/* ss */ cgfs[3],
		regs[REG_CR2]
	);
}


static void dump_stack(void *rsp)
{
	const size_t len = 128;
	pr_intr("  RSP Dump:\n");
	if (likely(is_valid_addr(rsp, len)))
		VT_HEXDUMP(rsp, len);
	else
		pr_intr("  RSP is invalid!\n\n");
}


static int ___emerg_handler(int sig, siginfo_t *si, ucontext_t *ctx)
{
	/* TODO: extract information from @si */
	(void)si;

	int is_recoverable, is_emerg_event;
	mcontext_t *mctx = &ctx->uc_mcontext;
	uintptr_t *regs = (uintptr_t *)&mctx->gregs;
	void *rip = (void *)regs[REG_RIP];

	if (unlikely(sig == SIGSEGV)) {
		is_emerg_event = 0;
		is_recoverable = 0;
	} else {
		is_emerg_event = is_emerg_pattern(rip);

		/* TODO: There may be other recoverable events. */
		is_recoverable = is_emerg_event;
	}

	if (likely(is_emerg_event))
		print_emerg_notice((uintptr_t)rip);

	pr_intr("  Signal: %d; is_recoverable = %d;\n", sig,
		is_recoverable);

	dump_register(regs);
	dump_stack((void *)regs[REG_RSP]);
	print_backtrace((uintptr_t)rip);

	if (likely(is_recoverable))
		emerg_recover(regs);

	if (likely(vfd != -1)) {
		close(vfd);
		// unlink(emerg_file_tmp);
		vfd = -1;
	}
	return is_recoverable;
}


static void __emerg_handler(int sig, siginfo_t *si, ucontext_t *ctx)
{
	int is_recoverable;
	emerg_callback_t pre_emerg_print_trace = __pre_emerg_print_trace;
	emerg_callback_t post_emerg_print_trace = __post_emerg_print_trace;

	__asm__ volatile(
		"mfence"
		: "+r"(pre_emerg_print_trace), "+r"(post_emerg_print_trace)
		:
		: "memory"
	);

	pr_intr("==========================================================\n");
	if (pre_emerg_print_trace)
		if (!pre_emerg_print_trace(sig, si, ctx))
			return;

	is_recoverable = ___emerg_handler(sig, si, ctx);

	if (post_emerg_print_trace)
		post_emerg_print_trace(sig, si, ctx);
	pr_intr("==========================================================\n");

	if (unlikely(!is_recoverable)) {
		pthread_mutex_unlock(&emerg_lock);
		abort();
		__builtin_unreachable();
	}
}


void emerg_handler(int sig, siginfo_t *si, void *arg)
{
	ucontext_t *ctx = (ucontext_t *)arg;

	if (unlikely(sig == SIGSEGV && !(emerg_init_bits & EMERG_INIT_SIGSEGV)))
		return;

	if (unlikely(sig == SIGFPE && !(emerg_init_bits & EMERG_INIT_SIGFPE)))
		return;

	pthread_mutex_lock(&emerg_lock);
	__emerg_handler(sig, si, ctx);
	pthread_mutex_unlock(&emerg_lock);
}


int emerg_init_handler(unsigned bits)
{
	struct sigaction act;

	if (bits & ~EMERG_INIT_ALL)
		return -EINVAL;

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = &emerg_handler;
	act.sa_flags = SA_SIGINFO | SA_ONSTACK;

	if (bits & EMERG_INIT_ALL) {
		stack_t st;
		st.ss_sp = alt_stack;
		st.ss_flags = 0;
		st.ss_size = sizeof(alt_stack);
		if (sigaltstack(&st, NULL))
			return -errno;
	}

	if (bits & (EMERG_INIT_BUG | EMERG_INIT_WARN | EMERG_INIT_SIGILL))
		sigaction(SIGILL, &act, NULL);

	if (bits & EMERG_INIT_SIGSEGV)
		sigaction(SIGSEGV, &act, NULL);

	if (bits & EMERG_INIT_SIGFPE)
		sigaction(SIGFPE, &act, NULL);

	emerg_init_bits = bits;
	return 0;
}

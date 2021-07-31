// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/include/cpu.h
 *
 *  CPU affinity header for TeaVPN2
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__CPU_H
#define TEAVPN2__CPU_H

#include <sched.h>
#include <unistd.h>
#include <teavpn2/base.h>


struct cpu_ret_info {
	int		online;
	int		nice;
	cpu_set_t	affinity;
};


int optimize_cpu_affinity(int need, struct cpu_ret_info *ret);
int optimize_process_priority(int nice_val, struct cpu_ret_info *ret);


#if __has_include("immintrin.h")
#  include <immintrin.h>
#endif

static __always_inline void __cpu_relax()
{
#if __has_include("immintrin.h")
	_mm_pause();
#else
#  if defined(__x86_64__)
	__asm__ volatile("rep; nop;" ::: "memory");
#  endif
#endif
}

#define cpu_relax __cpu_relax

#endif /* #ifndef TEAVPN2__CPU_H */

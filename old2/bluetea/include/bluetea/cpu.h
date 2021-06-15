// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/cpu.h
 *
 *  CPU header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__CPU_H
#define BLUETEA__CPU_H


#if defined(__x86_64__)
static __always_inline void __cpu_relax()
{
	__asm__ volatile("rep nop");
}
#  define cpu_relax __cpu_relax
#else
#  define cpu_relax()
#endif


#endif /* #ifndef BLUETEA__CPU_H */

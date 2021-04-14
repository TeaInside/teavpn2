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


static __always_inline void __cpu_relax()
{
	asm volatile("rep; nop;");
}

#define cpu_relax __cpu_relax

#endif /* #ifndef BLUETEA__CPU_H */

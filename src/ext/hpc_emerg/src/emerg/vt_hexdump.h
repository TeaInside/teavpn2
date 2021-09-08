// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi <ammarfaizi2@gmail.com>
 */

#ifndef EMERG__SRC__VT_HEXDUMP_H
#define EMERG__SRC__VT_HEXDUMP_H

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#define CHDOT(C) (((32 <= (C)) && ((C) <= 126)) ? (C) : '.')

inline static void vt_hexdump(void *ptr, size_t len)
{
	size_t i = 0, j, len2;
	unsigned char *c = ptr, *d;

	while (len) {
		pr_intr("  %s %#" PRIxPTR " | ",
			(i == 0 ? "%rsp =>" : "       "), (uintptr_t)c);
		d = c;
		len2 = len;
		for (j = 16; len && j; len--, j--) {
			pr_intr("%02x ", (unsigned)*c);
			c++;
		}
		pr_intr("|");
		for (j = 16; len2 && j; len2--, j--) {
			unsigned char dc = *d;
			pr_intr("%c", CHDOT(dc));
			d++;
		}
		pr_intr("|\n");
		i++;
	}
	pr_intr("\n");
}

#define VT_HEXDUMP vt_hexdump

#endif /* #ifndef EMERG__SRC__VT_HEXDUMP_H */

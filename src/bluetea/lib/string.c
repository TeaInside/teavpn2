// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/string.c
 *
 *  String library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>


char *trunc_str(char *str, size_t n)
{
	size_t len = strnlen(str, n);

	if (len < n)
		return str;

	str[n] = '\0';
	return str;
}

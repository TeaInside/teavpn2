// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/001_string/001_string.c
 *
 *  Test case for string helpers
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teavpn2/base.h>
#include <teavpn2/lib/string.h>
#include <criterion/criterion.h>


Test(string, trim_copy)
{
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "Hello World\0d  ";

	ptr = trim_cpy(str);
	cr_assert_eq(ptr, str, "Wrong trim_cpy return value");
	cr_assert(memcmp(str, cmp, sizeof(cmp)) == 0, "Wrong trim_cpy");
}


Test(string, trim_not_copy)
{
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "  Hello World\0 ";

	ptr = trim(str);

	cr_assert_eq(ptr, &str[2], "Wrong trim_not_copy return");
	cr_assert(memcmp(str, cmp, sizeof(cmp)) == 0, "Wrong trim_not_copy");
}

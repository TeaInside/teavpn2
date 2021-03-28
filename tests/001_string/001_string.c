// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/001_string/001_string.c
 *
 *  Test case for string helpers
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <teatest.h>
#include <teavpn2/base.h>
#include <teavpn2/lib/string.h>


static TEATEST(001_string, trim_copy)
{
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "Hello World\0d  ";

	ptr = trim_cpy(str);
	TQ_ASSERT(ptr == str);
	TQ_ASSERT(memcmp(str, cmp, sizeof(cmp)) == 0);

	return 0;
}


static TEATEST(001_string, trim_not_copy)
{
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "  Hello World\0 ";

	ptr = trim(str);

	TQ_ASSERT(ptr == &str[3]);
	TQ_ASSERT(memcmp(str, cmp, sizeof(cmp)) == 0);

	return 0;
}


int main(void)
{
	int ret;
	const test_entry_t entry[] = {
		TEATEST_FN(001_string, trim_copy),
		TEATEST_FN(001_string, trim_not_copy),
		NULL
	};

	ret = init_test(entry);
	if (ret != 0)
		return ret;

	ret = run_test(entry);
	return ret; 
}

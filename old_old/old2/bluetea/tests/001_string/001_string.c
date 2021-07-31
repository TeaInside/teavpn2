// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/tests/001_string/001_string.c
 *
 *  Test case for string helpers
 *
 *  Copyright (C) 2021  Ammar Faizi
 */
#include <bluetea/teatest.h>
#include <bluetea/base.h>
#include <bluetea/lib/string.h>


static TEATEST(001_string, trim_copy)
{
	TQ_START;
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "Hello World\0d  ";

	ptr = trim_cpy(str);
	TQ_ASSERT(ptr == str);
	TQ_ASSERT(memcmp(str, cmp, sizeof(cmp)) == 0);

	TQ_RETURN;
}


static TEATEST(001_string, trim_not_copy)
{
	TQ_START;
	char *ptr;
	char str[] = "  Hello World  ";
	char cmp[] = "  Hello World\0 ";

	ptr = trim(str);

	TQ_ASSERT(ptr == &str[2]);
	TQ_ASSERT(memcmp(str, cmp, sizeof(cmp)) == 0);

	TQ_RETURN;
}


static TEATEST(001_string, htmlspecialchars)
{
	TQ_START;
	size_t len = 0;
	char out[1024];

	{
		TQ_VOID(memset(out, 0, sizeof(out)));
		const char in[] = "Hello World";
		size_t inlen    = sizeof(in) - 1;
		TQ_VOID(len = htmlspecialchars(out, sizeof(out), in, inlen));
		TQ_ASSERT(len == sizeof(in));
		TQ_ASSERT(!memcmp(out, in, len));
	}


	{
		TQ_VOID(memset(out, 0, sizeof(out)));
		const char in[] = "<a href=\"https://www.google.com\">Google</a>";
		const char ex[] = "&lt;a href=&quot;https://www.google.com&quot;&gt;Google&lt;/a&gt;";
		size_t inlen    = sizeof(in) - 1;
		TQ_VOID(len = htmlspecialchars(out, sizeof(out), in, inlen));
		TQ_ASSERT(len == sizeof(ex));
		TQ_ASSERT(!memcmp(out, ex, len));
	}


	{
		TQ_VOID(memset(out, 0, sizeof(out)));
		const char in[]  = "<a href=\"https://www.google.com\">Google</a><<>>";
		const char _ex[] = "&lt;a href=&quot;https://www.google.com&quot;&gt;Google&lt;/a&gt;&lt;&lt;&gt;&gt;";
		const char ex[]  = "&lt;a href=&quot;https://www.google.com&quot;&gt;Google&lt;/a&gt;&lt;&lt;&gt;\0\0\0\0";
		size_t inlen     = sizeof(in) - 1;

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex), in, inlen));
		TQ_ASSERT(len == sizeof(_ex));
		TQ_ASSERT(!memcmp(out, _ex, sizeof(_ex)));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 1, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 4);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 2, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 4);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 3, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 4);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 4, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 4);
		TQ_ASSERT(!memcmp(out, _ex, len));


		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 5, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 8);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 6, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 8);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 7, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 8);
		TQ_ASSERT(!memcmp(out, _ex, len));

		TQ_VOID(len = htmlspecialchars(out, sizeof(_ex) - 8, in, inlen));
		TQ_ASSERT(len == sizeof(ex) - 8);
		TQ_ASSERT(!memcmp(out, _ex, len));
	}

	TQ_RETURN;
}

extern const test_entry_t test_entry_arr[];
const test_entry_t test_entry_arr[] = {
	FN_TEATEST(001_string, trim_copy),
	FN_TEATEST(001_string, trim_not_copy),
	FN_TEATEST(001_string, htmlspecialchars),
	NULL
};

// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/tests/001_string/strtrim.h
 *
 *  Test case for string library.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>

/*
 * Test strtriml (explicit length)
 */
static BLUETEST(001_string, test_strtriml)
{
	TQ_START;
	{
		/* Test simple leading spaces. */
		#define THE_STR "    ABCDEFGH"
		char *ret = NULL;
		char str[] = THE_STR;

		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));

		/* Must return a pointer to the first non-whitespace char. */
		TQ_ASSERT(ret == str + 4);

		/* Must not alter leading spaces, hence no changes were made. */
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));

		#undef THE_STR
	}


	{
		/* Test simple trailing spaces. */
		#define THE_STR "ABCDEFGH    "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "ABCDEFGH\0   ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test simple leading and trailing spaces. */
		#define THE_STR "    ABCDEFGH    "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str + 4);
		TQ_ASSERT(!memcmp(str, "    ABCDEFGH\0   ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test variant whitespace. */
		#define THE_STR "\t\f\v\tABCDEFGH\r\n\n "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str + 4);
		TQ_ASSERT(!memcmp(str, "\t\f\v\tABCDEFGH\0\n\n ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test unsigned chars. */
		#define THE_STR "\xf0\xff\x7f"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test all spaces. */
		#define THE_STR "\t\v\r\n\v\f"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str + sizeof(THE_STR) - 1);
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test empty string. */
		#define THE_STR "\0\0\0\0\0\0\0"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length. */
		#define THE_STR " 123456789"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, 5));
		TQ_ASSERT(ret == str + 1);
		TQ_ASSERT(!memcmp(str, " 1234\0" "6789", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 1). */
		#define THE_STR " 1234  "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, 5));
		TQ_ASSERT(ret == str + 1);
		TQ_ASSERT(!memcmp(str, " 1234\0" " ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 2). */
		#define THE_STR "       "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, 5));
		TQ_ASSERT(ret == str + 5);
		TQ_ASSERT(!memcmp(str, "     \0 ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 3). */
		#define THE_STR "\r\n\t\f\v  "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, 4));
		TQ_ASSERT(ret == str + 4);
		TQ_ASSERT(!memcmp(str, "\r\n\t\f\0  ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test don't trim. */
		#define THE_STR "AAAAAAA"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml(str, sizeof(str) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "AAAAAAA", sizeof(THE_STR)));
		#undef THE_STR
	}
	TQ_RETURN;
}


/*
 * Test strtrim (implicit length).
 */
static BLUETEST(001_string, test_strtrim)
{
	TQ_START;
	/*
	 * No need so many tests, we trust in strtrim
	 * as long as strtriml does the job correctly.
	 * Because strtrim internally calls strtriml.
	 */
	char *ret = NULL;
	char my_str[] = "   012345   ";
	TQ_VOID(ret = strtrim(my_str));
	TQ_ASSERT(ret == my_str + 3);
	TQ_ASSERT(!memcmp(ret - 3, "   ", 3));
	TQ_ASSERT(!memcmp(ret + 6, "\0  ", 3));
	TQ_RETURN;
}

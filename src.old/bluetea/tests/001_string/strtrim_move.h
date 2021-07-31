// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/tests/001_string/strtrim_move.h
 *
 *  Test case for string library.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>

/*
 * Test strtriml_move (explicit length).
 */
static BLUETEST(001_string, test_strtriml_move)
{
	TQ_START;
	{
		/* Test simple leading spaces. */
		#define THE_STR "    ABCDEFGHI"
		char *ret = NULL;
		char str[] = THE_STR;

		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));

		/* Must return the same pointer with the first argument. */
		TQ_ASSERT(ret == str);

		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI", sizeof("ABCDEFGHI")));

		/* Must not alter uneeded area. */
		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI\0GHI", sizeof(str)));

		#undef THE_STR
	}


	{
		/* Test simple trailing spaces. */
		#define THE_STR "ABCDEFGHI    "
		char *ret = NULL;
		char str[] = THE_STR;

		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));

		/* Must return the same pointer with the first argument. */
		TQ_ASSERT(ret == str);

		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI", sizeof("ABCDEFGHI")));

		/* Must not alter uneeded area. */
		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI\0   ", sizeof(str)));

		#undef THE_STR
	}


	{
		/* Test simple leading and trailing spaces. */
		#define THE_STR "   ABCDEFGHI    "
		char *ret = NULL;
		char str[] = THE_STR;

		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));

		/* Must return the same pointer with the first argument. */
		TQ_ASSERT(ret == str);

		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI", sizeof("ABCDEFGHI")));

		/* Must not alter uneeded area. */
		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI\0HI    ", sizeof(str)));

		#undef THE_STR
	}


	{
		/* Test variant whitespace. */
		#define THE_STR "\t\f\v\tABCDEFGHI\r\n\n "
		char *ret = NULL;
		char str[] = THE_STR;

		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));

		/* Must return the same pointer with the first argument. */
		TQ_ASSERT(ret == str);

		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI", sizeof("ABCDEFGHI")));

		/* Must not alter uneeded area. */
		TQ_ASSERT(!memcmp(ret, "ABCDEFGHI\0GHI\r\n\n ", sizeof(str)));

		#undef THE_STR
	}


	{
		/* Test unsigned chars. */
		#define THE_STR "\xf0\xff\x7f"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test all spaces. */
		#define THE_STR "\t\v\r\n\v\f"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "\0\v\r\n\v\f", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test empty string. */
		#define THE_STR "\0\0\0\0\0\0\0"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(THE_STR) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, THE_STR, sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length. */
		#define THE_STR " 123456789"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, 5));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "1234\0" "56789", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 1). */
		#define THE_STR " 1234  "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, 5));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "1234\0  ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 2). */
		#define THE_STR "       "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, 5));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "\0      ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test use shorter length than C string length (extra 3). */
		#define THE_STR "\r\n\t\f\v  "
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, 4));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "\0\n\t\f\v  ", sizeof(THE_STR)));
		#undef THE_STR
	}


	{
		/* Test don't trim. */
		#define THE_STR "AAAAAAA"
		char *ret = NULL;
		char str[] = THE_STR;
		TQ_ASSERT_S(ret = strtriml_move(str, sizeof(str) - 1));
		TQ_ASSERT(ret == str);
		TQ_ASSERT(!memcmp(str, "AAAAAAA", sizeof(THE_STR)));
		#undef THE_STR
	}
	TQ_RETURN;
}


/*
 * Test strtrim_move (implicit length).
 */
static BLUETEST(001_string, test_strtrim_move)
{
	TQ_START;
	/*
	 * No need so many tests, we trust in strtrim_move
	 * as long as strtriml_move does the job correctly.
	 * Because strtrim_move internally calls strtriml_move.
	 */
	char *ret = NULL;
	char my_str[] = "   012345   ";
	TQ_VOID(ret = strtrim_move(my_str));
	TQ_ASSERT(ret == my_str);
	TQ_ASSERT(!memcmp(my_str, "012345\0" "45   ", sizeof(my_str)));
	TQ_RETURN;
}

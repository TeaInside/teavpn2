// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/tests/001_string/strtrim.h
 *
 *  Test case for string library.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <string.h>
#include <bluetea/lib/string.h>


/*
 * Test htmlspecialchars
 */
static BLUETEST(001_string, test_htmlspecialcharsl)
{
	TQ_START;
	{
		size_t len = 0;
		const char str[] = "Hello World";
		const char esc[] = "Hello World";
		char out[sizeof(esc)] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(esc));
		TQ_ASSERT(!memcmp(out, esc, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<a href=\"https://www.google.com/test?a=1&b=2&c=3&d=4\"><b>Hello World!</p></a>";
		const char esc[] = "&lt;a href=&quot;https://www.google.com/test?a=1&amp;b=2&amp;c=3&amp;d=4&quot;&gt;&lt;b&gt;Hello World!&lt;/p&gt;&lt;/a&gt;";
		char out[sizeof(esc)] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(esc));
		TQ_ASSERT(!memcmp(out, esc, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 1] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 2] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 3] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 4] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/";
		char out[sizeof(esc) - 5] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "&a&";
		const char exp[] = "&amp;a\0amp;";
		char out[sizeof("&amp;a")] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, strlen(str)));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
		TQ_RETURN;
	}


	{
		size_t len = 0;
		const char str[] = "\0\0\0\0  &<\"  \">&  ";
		const char exp[] = "\0\0\0\0  &amp;&lt;&quot;  &quot;&gt;&amp;  ";
		char out[sizeof(exp)] = {0};

		TQ_ASSERT_S(len = htmlspecialcharsl(out, sizeof(out), str, sizeof(str) - 1));
		TQ_ASSERT(len == sizeof(exp) - 1);
		TQ_ASSERT(!memcmp(out, exp, sizeof(out)));
	}
	TQ_RETURN;
}




/*
 * Test htmlspecialchars
 */
static BLUETEST(001_string, test_htmlspecialchars)
{
	TQ_START;
	{
		size_t len = 0;
		const char str[] = "Hello World";
		const char esc[] = "Hello World";
		char out[sizeof(esc)] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(esc));
		TQ_ASSERT(!memcmp(out, esc, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<a href=\"https://www.google.com/test?a=1&b=2&c=3&d=4\"><b>Hello World!</p></a>";
		const char esc[] = "&lt;a href=&quot;https://www.google.com/test?a=1&amp;b=2&amp;c=3&amp;d=4&quot;&gt;&lt;b&gt;Hello World!&lt;/p&gt;&lt;/a&gt;";
		char out[sizeof(esc)] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(esc));
		TQ_ASSERT(!memcmp(out, esc, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 1] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 2] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 3] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 4] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr=\"123&amp;\">&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&quot;123&amp;amp;&quot;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/";
		char out[sizeof(esc) - 5] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "<p attr='123&amp;'>&amp;&amp;&gt;&lg;</p>";
		const char esc[] = "&lt;p attr=&#039;123&amp;amp;&#039;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p&gt;";
		const char exp[] = "&lt;p attr=&#039;123&amp;amp;&#039;&gt;&amp;amp;&amp;amp;&amp;gt;&amp;lg;&lt;/p";
		char out[sizeof(esc) - 2] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(exp, esc, sizeof(exp) - 1));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "&a&";
		const char exp[] = "&amp;a\0amp;";
		char out[sizeof("&amp;a")] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!strncmp(out, exp, sizeof(out)));
		TQ_RETURN;
	}


	{
		const char str[] = "\0\0\0\0  &<\"  \">&  ";
		const char exp[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0";
		char out[sizeof(exp)] = {0};

		TQ_ASSERT_S(htmlspecialchars(out, sizeof(out), str) == 0);
		TQ_ASSERT(!memcmp(out, exp, sizeof(out)));
	}


	{
		size_t len = 0;
		const char str[] = "A&&&&\0garbage value";
		const char exp[] = "A&amp;&amp;&amp;&amp;\0\0\0\0\0\0\0\0\0\0\0";
		char out[sizeof(exp)] = {0};

		TQ_ASSERT_S(len = htmlspecialchars(out, sizeof(out), str));
		TQ_ASSERT(len == strlen(exp));
		TQ_ASSERT(!memcmp(out, exp, sizeof(out)));
	}
	TQ_RETURN;
}

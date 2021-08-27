// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/string/strtrim.c
 *
 *  String library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>


__no_inline char *strtrim(char *str)
{
	/* TODO: Don't waste time just for strlen */
	return strtriml(str, strlen(str));
}


__no_inline char *strtriml(char *str, size_t len)
{
	char *end;

	if (unlikely(len == 0))
		return str;


	/*
	 * We assume that `str + len` is the location of the NUL char
	 */
	end = str + len - 1;


	while (is_ws(*str)) {

		if (str == &end[1]) {
			*str = '\0';
			return str;
		}

		str++;
	}


	if (*str == '\0' && str == &end[1]) {
		/*
		 * All spaces C string, or empty C string will go here.
		 */
		return str;
	}


	while (is_ws(*end))
		end--;


	end[1] = '\0';
	return str;
}


__no_inline char *strtrim_move(char *str)
{
	/* TODO: Don't waste time just for strlen */
	return strtriml_move(str, strlen(str));
}


__no_inline char *strtriml_move(char *str, size_t len)
{
	size_t trimmed_len;
	char *orig = str, *end;

	if (unlikely(len == 0))
		return orig;


	/*
	 * We assume that `str + len` is the location of the NUL char
	 */
	end = str + len - 1;


	while (is_ws(*str)) {

		if (str == &end[1]) {
			*orig = '\0';
			return orig;
		}

		str++;
	}


	if (*str == '\0' && str == &end[1]) {
		/*
		 * All spaces C string, or empty C string will go here.
		 */
		*orig = '\0';
		return orig;
	}


	while (is_ws(*end))
		end--;


	trimmed_len = (size_t)(end - str) + 1u;
	if (orig != str)
		memmove(orig, str, trimmed_len);

	orig[trimmed_len] = '\0';
	return orig;
}

// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/lib/string.c
 *
 *  String library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/lib/string.h>
#include <stdlib.h>

char *trunc_str(char *str, size_t n)
{
	size_t len = strnlen(str, n);

	if (len < n)
		return str;

	str[n] = '\0';
	return str;
}


/*
 *
 * Thanks to PHP
 * https://github.com/php/php-src/blob/e9d78339e7ff2edb8a1eda93d047ccaac25efa24/ext/standard/exec.c#L388-L468
 *
 */
char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len)
{
	size_t y = 0;
	size_t l = (len > 0) ? len : strlen(str);
	size_t x;
	char *cmd;

	if (alloc == NULL)
		/* Worst case */
		cmd = (char *)malloc((sizeof(char) * l * 4) + 1);
	else
		cmd = alloc;

#ifdef WIN32
	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif

	for (x = 0; x < l; x++) {
		switch (str[x]) {
#ifdef WIN32
		case '"':
		case '%':
		case '!':
			cmd[y++] = ' ';
			break;
#else
		case '\'':
			cmd[y++] = '\'';
			cmd[y++] = '\\';
			cmd[y++] = '\'';
#endif
		fallthrough;
		default:
			cmd[y++] = str[x];
		}
	}

#ifdef WIN32
	if (y > 0 && '\\' == cmd[y - 1]) {
		int k = 0, n = y - 1;
		for (; n >= 0 && '\\' == cmd[n]; n--, k++);
		if (k % 2) {
			cmd[y++] = '\\';
		}
	}
	cmd[y++] = '"';
#else
	cmd[y++] = '\'';
#endif

	cmd[y] = '\0';

	if (res_len != NULL)
		*res_len = y;

	return cmd;
}

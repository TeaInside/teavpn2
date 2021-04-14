// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/lib/string.c
 *
 *  String library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <bluetea/lib/string.h>


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

#define HEQ(C) ((*head) == (C))
#define TEQ(C) ((*tail) == (C))


char *trim_len(char *head, size_t len, size_t *res_len)
{
	char *tail  = &(head[len - 1]);
	bool move_t = false;

	while ((len > 0) && (HEQ(' ') || HEQ('\n') || HEQ('\r') || HEQ('\v'))) {
		head++;
		len--;
	}

	while ((len > 0) && (TEQ(' ') || TEQ('\n') || TEQ('\r') || TEQ('\v'))) {
		tail--;
		len--;
		move_t = true;
	}

	if ((len > 0) && move_t)
		*(tail + 1) = '\0';

	if (res_len != NULL)
		*res_len = len;

	return head;
}


char *trim_len_cpy(char *head, size_t len, size_t *res_len)
{
	char *start = head;
	char *tail  = &(head[len - 1]);
	bool move_h = false;

	while ((len > 0) && (HEQ(' ') || HEQ('\n') || HEQ('\r') || HEQ('\v'))) {
		head++;
		len--;
		move_h = true;
	}

	while ((len > 0) && (TEQ(' ') || TEQ('\n') || TEQ('\r') || TEQ('\v'))) {
		tail--;
		len--;
	}

	if (move_h) {
		if (len > 0)
			memmove(start, head, len);

		*(start + len) = '\0';
	}

	if (res_len != NULL)
		*res_len = len;

	return start;
}


char *trim(char *str)
{
	return trim_len(str, strlen(str), NULL);
}


char *trim_cpy(char *str)
{
	return trim_len_cpy(str, strlen(str), NULL);
}


char *trunc_str(char *str, size_t n)
{
	size_t len = strnlen(str, n);

	if (len < n)
		return str;

	str[n] = '\0';
	return str;
}


void *memzero_explicit(void *s, size_t n)
{
	return memset(s, '\0', n);
}


int memcmp_explicit(const void *s1, const void *s2, size_t n)
{
	return memcmp(s1, s2, n);
}

static const unsigned char hexchars[] = "0123456789ABCDEF";

/*
 * Thanks to PHP
 * https://github.com/php/php-src/blob/23961ef382e1005db6f8c08f3ecc0002839388a7/ext/standard/url.c#L459-L555
 */
char *urlencode(char *alloc, const char *s, size_t len, bool raw)
{
	register unsigned char c;
	unsigned char *to;
	unsigned char const *from, *end;
	char *start;

	from = (const unsigned char *)s;
	end = (const unsigned char *)s + len;

	if (alloc == NULL) {
		start = malloc((len * 3ul) + 1ul);
	} else {
		start = alloc;
	}

	to = (unsigned char *)start;

	while (from < end) {
		c = *from++;

		if (!raw && c == ' ') {
			*to++ = '+';
		} else if ((c < '0' && c != '-' && c != '.') ||
				(c < 'A' && c > '9') ||
				(c > 'Z' && c < 'a' && c != '_') ||
				(c > 'z' && (!raw || c != '~'))) {
			to[0] = '%';
			to[1] = hexchars[c >> 4];
			to[2] = hexchars[c & 15];
			to += 3;
		} else {
			*to++ = c;
		}
	}
	*to = '\0';

	return start;
}


size_t htmlspecialchars(char * restrict _output, size_t outlen,
			const char * restrict _input, size_t inlen)
{
	struct html_char_map {
		const char	to[8];
		const uint8_t	len;
	};

	static const struct html_char_map html_map[0xffu] = {
		['<'] = {"&lt;",	4},
		['>'] = {"&gt;",	4},
		['"'] = {"&quot;",	6},
		['&'] = {"&amp;",	5},
	};


	size_t j = 0;
	uint8_t len = 0;
	unsigned char * restrict output = (unsigned char *)_output;
	const unsigned char * restrict input  = (const unsigned char *)_input;
	const unsigned char *in_end = input + inlen;

	while (likely(input < in_end)) {
		const unsigned char *cp;
		const struct html_char_map *map_to = &html_map[(size_t)*input];

		if (likely(*map_to->to == '\0')) {
			cp  = input;
			len = 1;
		} else {
			cp  = (const unsigned char *)map_to->to;
			len = map_to->len;
		}

		if (unlikely((j + len - 1) >= outlen))
			break;

		memcpy(&output[j], cp, len);
		j += len;
		input++;
	}

	if (likely(outlen > 0)) {
		if (unlikely((j + 1) > outlen))
			j -= len;
		output[++j] = '\0';
	}

	return j;
}

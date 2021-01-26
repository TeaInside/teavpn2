

#ifndef __TEAVPN2__GLOBAL__HELPERS__STRING_H
#define __TEAVPN2__GLOBAL__HELPERS__STRING_H

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/**
 * @param char x
 * @return char
 */
inline static char my_tolower(char x)
{
	return ('A' <= x && x <= 'Z') ? x + 32 : x;
}


/**
 * @param char x
 * @return char
 */
inline static char my_toupper(char x)
{
	return ('a' <= x && x <= 'z') ? x - 32 : x;
}

#define HEQ(C) ((*head) == (C))
#define TEQ(C) ((*tail) == (C))

/**
 * @param char *str
 * @param size_t len
 * @param size_t *res_ken
 * @return char *
 */
inline static char *trim_len(char *head, size_t len, size_t *res_len)
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


/**
 * @param char   *head
 * @param size_t len
 * @param size_t *res_ken
 * @return char *
 */
inline static char *trim_len_cpy(char *head, size_t len, size_t *res_len)
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


/**
 * @param char *str
 */
inline static char *trim(char *str)
{
	return trim_len(str, strlen(str), NULL);
}


/**
 * @param char *str
 * @return char *
 */
inline static char *trim_cpy(char *str)
{
	return trim_len_cpy(str, strlen(str), NULL);
}

#endif /* #ifndef __TEAVPN2__GLOBAL__HELPERS__STRING_H */

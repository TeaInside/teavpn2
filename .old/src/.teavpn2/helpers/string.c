

#include <teavpn2/global/helpers/string.h>


/** 
 * @param char	   *alloc
 * @param const char *str
 * @retur char *
 */
char *escapeshellarg(char *alloc, const char *str, size_t len, size_t *res_len)
{
	size_t y = 0;
	size_t l = (len > 0) ? len : strlen(str);
	size_t x;
	char   *cmd;

	if (alloc == NULL) {
		/* Worst case */
		cmd = (char *)malloc((sizeof(char) * l * 4) + 1);
	} else {
		cmd = alloc;
	}

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
		/* fall-through */
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

/**
 * @param char *str
 * @param size_t len
 * @param size_t *res_ken
 * @return char *
 */
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


/**
 * @param char   *head
 * @param size_t len
 * @param size_t *res_ken
 * @return char *
 */
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


/**
 * @param char *str
 */
char *trim(char *str)
{
	return trim_len(str, strlen(str), NULL);
}


/**
 * @param char *str
 * @return char *
 */
char *trim_cpy(char *str)
{
	return trim_len_cpy(str, strlen(str), NULL);
}

/**
 * @param char *str
 * @return char *
 */
char *trunc_str(char *str, size_t n)
{
	size_t len = strnlen(str, n);

	if (len < n)
		return str;

	str[n] = '\0';
	return str;
}

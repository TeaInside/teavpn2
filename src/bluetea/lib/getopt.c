// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/lib/getopt.c
 *
 *  Getopt library
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bluetea/lib/getopt.h>


static inline bool is_end_of_getopt_long(const struct bt_getopt_long *in)
{
	const struct bt_getopt_long cmp = GETOPT_LONG_STRUCT_END;

	/*
	 * Don't use memcmp!
	 *
	 * According to C standards (C99, C11 and C18):
	 * The value of padding bytes when storing values in
	 * structures or unions is unspecified (6.2.6.1).
	 *
	 */
	return (
		(cmp.opt == in->opt) &&
		(cmp.arg_req == in->arg_req) &&
		(cmp.val == in->val)
	);
}


static int track_getopt_long(char *cur_arg, size_t cur_len, int cur_idx,
			     struct bt_getopt_wr *wr)
{
	char **argv = wr->argv;
	const struct bt_getopt_long *long_opt = wr->long_opt;

	if (long_opt == NULL) {
		wr->retval = cur_arg;
		return BT_GETOPT_NON_OPT;
	}

	/* Skip the '--' chars */
	cur_arg += 2;
	cur_len -= 2;

	while (!is_end_of_getopt_long(long_opt)) {
		int val;
		char *take_arg = NULL;
		const char *opt = long_opt->opt;
		size_t opt_len = strlen(opt);

		if (strncmp(opt, cur_arg, opt_len)) {
			long_opt++;
			continue;
		}

		/*
		 * Handle long option that uses `=` as separator
		 *
		 * `./app --an-option=value`
		 */
		if (cur_len > opt_len && cur_arg[opt_len] != '=') {
			long_opt++;
			continue;
		}

		val = long_opt->val;

		switch (long_opt->arg_req) {
		case REQUIRED_ARG:
		case OPTIONAL_ARG:
			/*
			 * Is it an argument with `=` value separator?
			 */
			if (cur_len > opt_len) {
				take_arg = cur_arg + opt_len + 1;
			} else {
				take_arg = argv[cur_idx + 1];
				if (*take_arg != '-')
					wr->cur_idx++;
				else
					take_arg = NULL;
			}

			wr->retval = take_arg;
			if (long_opt->arg_req == REQUIRED_ARG && !take_arg)
				return BT_GETOPT_MISSING_ARG;

			return val;
		case NO_ARG:
			wr->retval = NULL;
			return val;
		case EMPTY_STRUCT:
		default:
			return BT_GETOPT_EINVAL;
		}

	}


	wr->retval = NULL;
	return BT_GETOPT_UNKNOWN_OPT;
}


static int track_getopt_short(char *cur_arg, size_t cur_len, int cur_idx,
			      struct bt_getopt_wr *wr)
{
	char **argv = wr->argv;
	unsigned char c = (unsigned char)cur_arg[1];
	const unsigned char *short_opt = (const unsigned char *)wr->short_opt;


	if (short_opt == NULL) {
		wr->retval = cur_arg;
		return BT_GETOPT_NON_OPT;
	}


	while (*short_opt) {
		char *take_arg = NULL;

		if (*short_opt != c) {
			while (*(++short_opt) == ':');
			continue;
		}

		if (short_opt[1] != ':') {
			/*
			 * Option does not take value.
			 */
			wr->retval = NULL;
			return c;
		}

		if (cur_len > 2) {
			/*
			 * Merged value
			 *
			 * `./server -H0.0.0.0 -P55555`
			 */
			take_arg = cur_arg + 2;
		} else {
			take_arg = argv[cur_idx + 1];
			if (*take_arg != '-')
				wr->cur_idx++;
			else
				take_arg = NULL;
		}


		wr->retval = take_arg;
		if (short_opt[2] == ':') {
			/* 
			 * Option takes optional value
			 */
			return c;
		}


		/*
		 * Option takes required value
		 */
		if (take_arg == NULL)
			return BT_GETOPT_MISSING_ARG;

		return c;
	}


	wr->retval = NULL;
	return BT_GETOPT_UNKNOWN_OPT;
}


int bt_getopt(struct bt_getopt_wr *wr)
{
	int ret = 0;
	int argc = wr->argc;
	int cur_idx = wr->cur_idx;
	char *cur_arg;
	size_t cur_len;

	if (cur_idx >= argc) {
		wr->retval = NULL;
		return BT_GETOPT_END;
	}

	cur_arg = wr->argv[cur_idx];
	cur_len = strlen(cur_arg);

	if (cur_len >= 2 && cur_arg[0] == '-') {
		if (cur_arg[1] == '-')
			ret = track_getopt_long(cur_arg, cur_len, cur_idx, wr);
		else
			ret = track_getopt_short(cur_arg, cur_len, cur_idx, wr);

		goto out;
	}

	wr->retval = cur_arg;
	ret = BT_GETOPT_NON_OPT;
out:
	wr->cur_idx++;
	return ret;
}

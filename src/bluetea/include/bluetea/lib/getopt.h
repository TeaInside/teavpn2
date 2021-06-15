// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/include/bluetea/lib/getopt.h
 *
 *  Getopt library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__LIB__GETOPT_H
#define BLUETEA__LIB__GETOPT_H

#include <errno.h>
#include <stddef.h>
#include <stdbool.h>


typedef enum _bt_getopt_req_arg {
	EMPTY_STRUCT	= 0,
	REQUIRED_VAL	= 1,
	OPTIONAL_VAL	= 2,
	NO_VAL		= 3
} bt_getopt_req_arg;


struct bt_getopt_long {
	const char			*opt;
	bt_getopt_req_arg		arg_req;
	unsigned char			val;
};


#define GETOPT_LONG_STRUCT_END {NULL, EMPTY_STRUCT, 0}


struct bt_getopt_wr {
	int				argc;
	char				**argv;
	const char			*short_opt;
	const struct bt_getopt_long	*long_opt;
	char				*retval;
	int				cur_idx;
};


#define BT_GETOPT_END		(-1)
#define BT_GETOPT_UNKNOWN_OPT	(-2)
#define BT_GETOPT_NON_OPT	(-3)
#define BT_GETOPT_EINVAL	(-4)
#define BT_GETOPT_MISSING_ARG	(-5)
#define BT_GETOPT_WANT_NO_VAL	(-6)

int bt_getopt(struct bt_getopt_wr *wr);


#endif /* #ifndef BLUETEA__LIB__GETOPT_H */

// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/include/bluetea/lib/getopt.h
 *
 *  Getopt library header
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef BLUETEA__LIB__GETOPT_H
#define BLUETEA__LIB__GETOPT_H

#include <errno.h>
#include <stdbool.h>


typedef enum _bt_getopt_req_arg {
	EMPTY_STRUCT	= 0,
	NO_ARG		= 1,
	REQUIRED_ARG	= 2,
	OPTIONAL_ARG	= 3,
} bt_getopt_req_arg;


struct bt_getopt_long {
	const char		*opt;
	bt_getopt_req_arg	arg_req;
	unsigned char		val;
};


struct bt_getopt_wr {
	int				argc;
	const char			**argv;
	const char			*short_opt;
	const struct bt_getopt_long	*long_opt;
	const char			*retval;
	int				cur_idx;
};


#define GETOPT_LONG_STRUCT_END {NULL, 0, 0}


#define BT_GETOPT_UNKNOWN	(-1)
#define BT_GETOPT_ENDED		(-2)
#define BT_GETOPT_NO_OPT	(-3)
#define BT_GETOPT_MISSING_ARG	(-4)
#define BT_GETOPT_EINVAL	(-5)

int bt_getopt(struct bt_getopt_wr *wr);


#endif /* #ifndef BLUETEA__LIB__GETOPT_H */

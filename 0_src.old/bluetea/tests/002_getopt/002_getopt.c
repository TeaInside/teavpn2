// SPDX-License-Identifier: GPL-2.0
/*
 *  bluetea/tests/002_string/002_getopt.c
 *
 *  Test case for getopt library.
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <string.h>
#include <bluetea/bluetest.h>
#include <bluetea/lib/getopt.h>



static BLUETEST(002_getopt, simple_long_opt)
{
	TQ_START;
	static const char *short_opt = NULL;
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",		REQUIRED_VAL,	'H'},
		{"bind-port",		REQUIRED_VAL,	'P'},
		{"daemon",		NO_VAL,		'D'},
		{"optional-arg",	OPTIONAL_VAL,	'O'},
		{"unused-arg",		REQUIRED_VAL,	'u'},
		GETOPT_LONG_STRUCT_END,
	};
	char *argv[] = {
		"server",
		"--bind-addr",
		"0.0.0.0",
		"--bind-port",
		"55555",
		"--optional-arg",
		"--daemon",
		"--optional-arg",
		"This is an optional value",
		"--unknown-option",
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NON_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[0]);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[2]);
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));
	TQ_ASSERT(wr.retval == argv[2]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[4]);
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));
	TQ_ASSERT(wr.retval == argv[4]);

	TQ_ASSERT(bt_getopt(&wr) == 'O'); /* Optional arg */
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[5]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'O'); /* Optional arg */
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[8]);
	TQ_ASSERT(!memcmp(wr.retval, "This is an optional value", sizeof("This is an optional value")));
	TQ_ASSERT(wr.retval == argv[8]);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


static BLUETEST(002_getopt, long_opt_with_eq_sign)
{
	TQ_START;
	static const char *short_opt = NULL;
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",		REQUIRED_VAL,	'H'},
		{"bind-port",		REQUIRED_VAL,	'P'},
		{"daemon",		NO_VAL,		'D'},
		{"optional-arg",	OPTIONAL_VAL,	'O'},
		{"unused-arg",		REQUIRED_VAL,	'u'},
		GETOPT_LONG_STRUCT_END,
	};
	char *argv[] = {
		"server",
		"--bind-addr=0.0.0.0",
		"--bind-port=55555",
		"--optional-arg",
		"--daemon",
		"--optional-arg=This is an optional value",
		"--unknown-option",
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NON_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[0]);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[1]);
	TQ_ASSERT(wr.retval == (argv[1] + sizeof("--bind-addr")));
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[2]);
	TQ_ASSERT(wr.retval == (argv[2] + sizeof("--bind-port")));
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[3]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[4]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[5]);
	TQ_ASSERT(wr.retval == (argv[5] + sizeof("--optional-arg")));
	TQ_ASSERT(!memcmp(wr.retval, "This is an optional value", sizeof("This is an optional value")));

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}

static BLUETEST(002_getopt, simple_short_opt)
{
	TQ_START;
	static const char *short_opt = "H:P:O::D";
	static const struct bt_getopt_long *long_opt = NULL;
	char *argv[] = {
		"server",
		"-H",
		"0.0.0.0",
		"-P",
		"55555",
		"-O", /* optional value */
		"-D",
		"-O",
		"This is an optional value",
		"-U", /* unknown option */
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};


	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NON_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[0]);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[2]);
	TQ_ASSERT(wr.retval == argv[2]);
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[4]);
	TQ_ASSERT(wr.retval == argv[4]);
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[5]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[8]);
	TQ_ASSERT(wr.retval == argv[8]);
	TQ_ASSERT(!memcmp(wr.retval, "This is an optional value", sizeof("This is an optional value")));

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[9]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}

static BLUETEST(002_getopt, short_opt_merged_val)
{
	TQ_START;
	static const char *short_opt = "H:P:O::D";
	static const struct bt_getopt_long *long_opt = NULL;
	char *argv[] = {
		"server",
		"-H0.0.0.0",
		"-P55555",
		"-O", /* optional value */
		"-D",
		"-OThis is an optional value",
		"-U", /* unknown option */
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		.argc = argc,
		.argv = argv,
		.short_opt = short_opt,
		.long_opt = long_opt,
		.retval = NULL,
		.cur_idx = 0
	};


	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NON_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[0]);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[1]);
	TQ_ASSERT(wr.retval == (argv[1] + sizeof("-H") - 1));
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[2]);
	TQ_ASSERT(wr.retval == (argv[2] + sizeof("-P") - 1));
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[3]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[4]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'O');
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[5]);
	TQ_ASSERT(wr.retval == (argv[5] + sizeof("-H") - 1));
	TQ_ASSERT(!memcmp(wr.retval, "This is an optional value", sizeof("This is an optional value")));

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN_OPT);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_END);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[6]);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


bluetest_entry_t test_entry[] = {
	FN_BLUETEST(002_getopt, simple_long_opt),
	FN_BLUETEST(002_getopt, long_opt_with_eq_sign),
	FN_BLUETEST(002_getopt, simple_short_opt),
	FN_BLUETEST(002_getopt, short_opt_merged_val),
	NULL
};

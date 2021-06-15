// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/tests/005_getopt/005_getopt.c
 *
 *  Test case for getopt
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <bluetea/teatest.h>
#include <bluetea/lib/getopt.h>


static TEATEST(005_getopt, simple_long_opt)
{
	TQ_START;
	static const char *short_opt = NULL;
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",	REQUIRED_ARG,	'H'},
		{"bind-port",	REQUIRED_ARG,	'P'},
		{"daemon",	NO_ARG,		'D'},
		GETOPT_LONG_STRUCT_END,
	};
	static const char *argv[] = {
		"server",
		"--bind-addr",
		"0.0.0.0",
		"--bind-port",
		"55555",
		"--daemon",
		"--unknown-option",
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));
	TQ_ASSERT(wr.retval == argv[2]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));
	TQ_ASSERT(wr.retval == argv[4]);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


static TEATEST(005_getopt, simple_short_opt1)
{
	TQ_START;
	static const char *short_opt = "H:P:D";
	static const struct bt_getopt_long *long_opt = NULL;
	static const char *argv[] = {
		"server",
		"-H",
		"0.0.0.0",
		"-P",
		"55555",
		"-D",
		"-U", /* unknown option */
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));
	TQ_ASSERT(wr.retval == argv[2]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));
	TQ_ASSERT(wr.retval == argv[4]);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


static TEATEST(005_getopt, simple_short_opt2)
{
	TQ_START;
	static const char *short_opt = "H:P:D";
	static const struct bt_getopt_long *long_opt = NULL;
	static const char *argv[] = {
		"server",
		"-H0.0.0.0",
		"-P55555",
		"-D",
		"-U", /* unknown option */
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));
	TQ_ASSERT(wr.retval == argv[2]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));
	TQ_ASSERT(wr.retval == argv[4]);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


static TEATEST(005_getopt, mix_short_and_long)
{
	TQ_START;
	static const char *short_opt = "H:P:D";
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",	REQUIRED_ARG,	'H'},
		{"bind-port",	REQUIRED_ARG,	'P'},
		{"daemon",	NO_ARG,		'D'},
		GETOPT_LONG_STRUCT_END,
	};
	static const char *argv[] = {
		"server",
		"--bind-addr",
		"0.0.0.0",
		"--bind-port",
		"55555",
		"--daemon",
		"--unknown-option",
		"-H",
		"1.1.1.1",
		"-P",
		"44444",
		"-D",
		"-U", /* unknown option */
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(!memcmp(wr.retval, "0.0.0.0", sizeof("0.0.0.0")));
	TQ_ASSERT(wr.retval == argv[2]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(!memcmp(wr.retval, "55555", sizeof("55555")));
	TQ_ASSERT(wr.retval == argv[4]);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN);
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == 'H');
	TQ_ASSERT(!memcmp(wr.retval, "1.1.1.1", sizeof("1.1.1.1")));
	TQ_ASSERT(wr.retval == argv[8]);

	TQ_ASSERT(bt_getopt(&wr) == 'P');
	TQ_ASSERT(!memcmp(wr.retval, "44444", sizeof("44444")));
	TQ_ASSERT(wr.retval == argv[10]);

	TQ_ASSERT(bt_getopt(&wr) == 'D');
	TQ_ASSERT(wr.retval == NULL);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_UNKNOWN);
	TQ_ASSERT(wr.retval == NULL);

	TQ_RETURN;
}


static TEATEST(005_getopt, missing1)
{
	TQ_START;
	static const char *short_opt = "H:P:D";
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",	REQUIRED_ARG,	'H'},
		{"bind-port",	REQUIRED_ARG,	'P'},
		{"daemon",	NO_ARG,		'D'},
		GETOPT_LONG_STRUCT_END,
	};
	static const char *argv[] = {
		"server",
		"--bind-addr", /* missng bind addr argument */
		"--bind-port",
		"55555",
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_MISSING_ARG);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[1]);
	TQ_ASSERT(wr.retval == NULL);


	TQ_RETURN;
}


static TEATEST(005_getopt, missing2)
{
	TQ_START;
	static const char *short_opt = "H:P:D";
	static const struct bt_getopt_long long_opt[] = {
		{"bind-addr",	REQUIRED_ARG,	'H'},
		{"bind-port",	REQUIRED_ARG,	'P'},
		{"daemon",	NO_ARG,		'D'},
		GETOPT_LONG_STRUCT_END,
	};
	static const char *argv[] = {
		"server",
		"-H", /* missng argument */
		"-P",
		"55555",
		NULL
	};
	int argc = (sizeof(argv) / sizeof(*argv)) - 1;
	struct bt_getopt_wr wr = {
		argc, argv, short_opt, long_opt, NULL, 0
	};

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_NO_OPT);
	TQ_ASSERT(!memcmp(wr.retval, "server", sizeof("server")));
	TQ_ASSERT(wr.retval == argv[0]);

	TQ_ASSERT(bt_getopt(&wr) == BT_GETOPT_MISSING_ARG);
	TQ_ASSERT(wr.argv[wr.cur_idx - 1] == argv[1]);
	TQ_ASSERT(wr.retval == NULL);


	TQ_RETURN;
}


extern const test_entry_t test_entry_arr[];
const test_entry_t test_entry_arr[] = {
	FN_TEATEST(005_getopt, simple_long_opt),
	FN_TEATEST(005_getopt, simple_short_opt),
	FN_TEATEST(005_getopt, mix_short_and_long),
	FN_TEATEST(005_getopt, missing1),
	FN_TEATEST(005_getopt, missing2),
	NULL
};

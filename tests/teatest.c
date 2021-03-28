// SPDX-License-Identifier: GPL-2.0-only
/*
 *  tests/teatest.c
 *
 *  Tea Test (Unit Test Framework for C project)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <teavpn2/base.h>

#include <teatest.h>
#include <execinfo.h>

static bool __want_to_run_test = false;
static uint32_t __total_credit = 0, __credit = 0;
#define BT_BUF_SIZE (0x8000u)

static void pr_backtrace()
{
	int nptrs;
	void *buffer[BT_BUF_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BT_BUF_SIZE);
	printf(" backtrace() returned %d addresses\n", nptrs);

	/* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
	would produce similar output to the following: */

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		exit(EXIT_FAILURE);
	}

	for (int j = 0; j < nptrs; j++)
		printf("    #%d %s\n", j, strings[j]);

	free(strings);
}


static void sig_handler(int sig)
{
	if (sig == SIGSEGV) {
		core_dump();
		panic("SIGSEGV caught!");
		pr_emerg("You crashed the program memory!");
		pr_emerg("Segmentation Fault (core dumped)");
		pr_emerg("===============================================");
		pr_backtrace();
		exit(1);
	} else if (sig == SIGABRT) {
		core_dump();
		panic("SIGABRT caught!");
		pr_emerg("Aborted (core dumped)");
		pr_emerg("===============================================");
		exit(1);
	}
	exit(0);
}


static void print_info(int ret, uint32_t total_credit, uint32_t credit)
{
	double accuracy;

	if (credit == 0 || total_credit == 0) {
		accuracy = 0;
	} else {
		accuracy = ((double)credit / (double)total_credit) * 100.0;
	}

	printf("==================================================\n");
	printf("\t\tSummary\n");
	printf("--------------------------------------------------\n");
	printf("   Last return value\t: %d\n", ret);
	printf("   Your accuracy\t: %.2f %c\n", accuracy, '%');
	printf("   Earned credit\t: %u of %u\n", credit, total_credit);
	printf("==================================================\n");
}


bool print_test(bool is_success, const char *func, const char *file, int line)
{
	if (is_success) {
		pr_notice("\x1b[32mTest passed\x1b[0m: %s() in %s line %d",
		  	  func, file, line);
	} else {
		pr_notice("\x1b[31mTest failed\x1b[0m: %s() in %s line %d",
		  	  func, file, line);
	}
	return is_success;
}


bool tq_assert_hook(void)
{
	return __want_to_run_test;
}



int init_test(const test_entry_t *tests)
{
	const test_entry_t *test_entry = tests;
	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	pr_notice("Initializing test...");
	__want_to_run_test = 0;
	while (*test_entry) {
		/*
		 * Calculate total credit
		 */
		(*test_entry++)(&__total_credit, &__credit);
	}

	return 0;
}



int run_test(const test_entry_t *tests)
{
	int ret = 0;
	const test_entry_t *test_entry = tests;
	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	pr_notice("Running test...");
	__want_to_run_test = 1;
	while (*test_entry) {
		ret = (*test_entry++)(&__total_credit, &__credit);
	}

	print_info(ret, __total_credit, __credit);
	return ret;
}

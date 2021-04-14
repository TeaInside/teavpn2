// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/teatest/teatest.c
 *
 *  Tea Test (Unit Test Framework for C project)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include "teatest.h"

#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <alloca.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <execinfo.h>

#include <bluetea/base.h>
#include <bluetea/lib/string.h>

extern char **environ;
extern const test_entry_t test_entry_arr[];

static bool is_exec = false;
static uint32_t __total_point = 0, __point = 0;
static int __pipe_wr_fd = -1;


bool tq_assert_is_exec(void)
{
	return is_exec;
}


void filename_resolve(char *buf, size_t bufsiz, const char *filename,
		      size_t len)
{
	char __fn0[len], __fn1[len];

	memcpy(__fn0, filename, len);
	memcpy(__fn1, filename, len);

	snprintf(buf, bufsiz, "%s/%s", basename(dirname(__fn0)),
		 basename(__fn1));
}


bool print_test(bool is_success, const char *func, const char *file, int line)
{
	if (is_success) {
		pr_notice("\x1b[32mTest passed\x1b[0m: %s in %s line %d", func,
			  file, line);
	} else {
		pr_notice("\x1b[31mTest failed\x1b[0m: %s in %s line %d", func,
			  file, line);
	}
	return is_success;
}

#define BT_BUF_SIZE (0x8000u)

static void pr_backtrace()
{
	int nptrs;
	void *buffer[BT_BUF_SIZE];
	char **strings;

	nptrs = backtrace(buffer, BT_BUF_SIZE);
	printf(" backtrace() returned %d addresses\n", nptrs);

	/*
	 * The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
	 * would produce similar output to the following:
	 */

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
	int err;
	point_t	data;
	ssize_t write_ret;

	/*
	 * Panic!
	 *
	 * Report total point!
	 */
	data.total_point = __total_point;
	data.point = __point;
	write_ret = write(__pipe_wr_fd, &data, sizeof(data));
	if (unlikely(write_ret < 0)) {
		err = errno;
		pr_err("write(): " PRERF, PREAR(err));
	}

	signal(sig, SIG_DFL);

	if (sig == SIGSEGV) {
		core_dump();
		panic("SIGSEGV caught!");
		pr_emerg("You crashed the program memory!");
		pr_emerg("Segmentation Fault (core dumped)");
	} else if (sig == SIGABRT) {
		core_dump();
		panic("SIGABRT caught!");
		pr_emerg("Aborted (core dumped)");
	}
	pr_emerg("===============================================");
	pr_backtrace();
	raise(sig);
	exit(1);
}


static int init_test(const char *pipe_write_fd, const test_entry_t *tests)
{
	int err;
	point_t	data;
	int pipe_wr_fd; /* Pipe write fd */
	ssize_t write_ret;
	const test_entry_t *test_entry = tests;

	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	__pipe_wr_fd = pipe_wr_fd = atoi(pipe_write_fd);
	pr_notice("Initializing test (pipe_wr_fd: %d)...", pipe_wr_fd);

	is_exec = false;
	while (*test_entry) {
		/*
		 * Calculate total point
		 */
		(*test_entry++)(&__total_point, &__point);

		/*
		 * Report total point to parent to prevent misinformation
		 * when panic.
		 */
		data.point = __point;
		data.total_point = __total_point;
		write_ret = write(pipe_wr_fd, &data, sizeof(data));
		if (unlikely(write_ret < 0)) {
			err = errno;
			pr_err("write(): " PRERF, PREAR(err));
		}
	}

	return 0;
}


static int run_test(const test_entry_t *tests)
{
	int err;
	int ret = 0;
	point_t	data;
	bool fail = false;
	ssize_t write_ret;
	const test_entry_t *test_entry = tests;

	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	pr_notice("Running test...");
	is_exec = true;
	while (*test_entry) {
		/*
		 * Execute test and calculate true/false point.
		 */
		ret = (*test_entry++)(&__total_point, &__point);
		if (ret != 0)
			fail = true;

		/*
		 * Report total point to parent.
		 */
		data.point = __point;
		data.total_point = __total_point;
		write_ret = write(__pipe_wr_fd, &data, sizeof(data));
		if (unlikely(write_ret < 0)) {
			err = errno;
			pr_err("write(): " PRERF, PREAR(err));
		}
	}

	for (int i = 0; i < 1000; i++)
		close(i);
	
	return fail ? 1 : 0;
}


static int fd_set_nonblock(int fd)
{
	int err;
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_GETFL, 0): " PRERF, fd, PREAR(err));
		return -err;
	}
	
	flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (unlikely(flags < 0)) {
		err = errno;
		pr_err("fcntl(%d, F_SETFL, %d): " PRERF, fd, flags, PREAR(err));
		return -err;
	}

	return flags;
}


static void print_info(int ret, uint32_t total_point, uint32_t point)
{
	int fd;
	double accuracy;

	if (point == 0 || total_point == 0) {
		accuracy = 0;
	} else {
		accuracy = ((double)point / (double)total_point) * 100.0;
	}

	fd = open("test_lock.tmp", O_RDWR | O_CREAT, S_IRWXU);
	if (unlikely(fd < 0)) {
		int err = errno;
		pr_err("open(\"test_lock.tmp\"): " PRERF, PREAR(err));
	}

	if (fd > 0)
		flock(fd, LOCK_EX);
	printf("==================================================\n");
	printf("\t\tSummary\n");
	printf("--------------------------------------------------\n");
	printf("   Last return value\t: %d\n", ret);
	printf("   Your accuracy\t: %.2f %c\n", accuracy, '%');
	printf("   Earned point\t\t: %u of %u\n", point, total_point);
	printf("==================================================\n");
	if (fd > 0)
		flock(fd, LOCK_UN);
	close(fd);
}


static int handle_wait(pid_t child, int pipe_fd[2])
{
	int err;
	int wstatus;
	int poll_ret;
	int exit_code;
	pid_t wait_ret;
	ssize_t read_ret;
	union {
		point_t	data;
		char	buf[sizeof(point_t)];
	} buf;
	struct pollfd fds[1];


	wait_ret = wait(&wstatus);
	if (!(WIFEXITED(wstatus) && (wait_ret == child))) {
		pr_err("Unknown error, please contact Ammar F");
		pr_err("Please also tell to him, how did you get into this error");
		return -1;
	}

	exit_code = WEXITSTATUS(wstatus);
	fds[0].fd = pipe_fd[0];
	fds[0].events = POLLIN;
	fds[0].revents = 0;


	while (true) {
		poll_ret = poll(fds, 1, 0);
		if (!poll_ret)
			break;

		read_ret = read(pipe_fd[0], buf.buf, sizeof(buf.buf));
		if (read_ret < 0) {
			err = errno;
			if (err != EAGAIN) {
				pr_err("read(): " PRERF, PREAR(err));
				break;
			}
		}
	}


	if (exit_code == 0) {
		/*
		 * All green!
		 */
		goto out_exit;
	}


	pr_err("\x1b[31mTEST FAILED!\x1b[0m");
	pr_err("Exit code: %d", exit_code);
	if (exit_code == 99) {
		pr_err("Error from valgrind detected");
		pr_err("Please read the error message from valgrind to diagnose "
		       "this problem");
		pr_err("Reading valgrind backtrace is not trivial, please be "
		       "serious!");
	}

out_exit:
	print_info(exit_code, buf.data.total_point, buf.data.point);
	return exit_code;
}


static int spawn_valgrind(int argc, char *argv[])
{
	int ret = 0;
	int err = 0;
	int pipe_fd[2];
	pid_t child_pid;
	int vla_argc;
	char **vla_argv;
	char pipe_fd_arg[16];


	/* (argc & 0xfu) allows max argc up to 15 */
	vla_argc  = (uint8_t)argc & 0xfu;

	/* Allocate more space for `pipe_fd_arg` */
	vla_argc += 1;


	if (unlikely(pipe(pipe_fd) < 0)) {
		err = errno;
		pr_err("pipe(): " PRERF, PREAR(err));
		return err;
	}


	ret = fd_set_nonblock(pipe_fd[0]);
	if (unlikely(err))
		return -ret;


	/* We share the `write pipe fd` to child via argument */
	snprintf(pipe_fd_arg, sizeof(pipe_fd_arg), "%d", pipe_fd[1]);
	vla_argv = alloca((size_t)(vla_argc + 1) * sizeof(*vla_argv));

	/* Copy arguments */
	memmove(&vla_argv[0], &argv[1], (size_t)(vla_argc - 2) * sizeof(*argv));
	vla_argv[vla_argc - 2] = argv[0];
	vla_argv[vla_argc - 1] = pipe_fd_arg;
	vla_argv[vla_argc - 0] = NULL;


	child_pid = fork();
	if (unlikely(child_pid < 0)) {
		err = errno;
		pr_err("fork(): " PRERF, PREAR(err));
		ret = err;
		goto out;
	}


	if (child_pid == 0) {

		/* We're the child process */
		execve(vla_argv[0], vla_argv, environ);

		/* execve won't return if success */
		err = errno;
		pr_err("execve(\"%s\"): " PRERF, vla_argv[0], PREAR(err));
		return err;
	}

	ret = handle_wait(child_pid, pipe_fd);
out:
	close(pipe_fd[0]);
	close(pipe_fd[1]);
	return ret;
}


int main(int argc, char *argv[])
{
	int ret;
	char fpath[0xffu];

	if (argc == 1)
		goto out_invalid;

	memzero_explicit(fpath, sizeof(fpath));

	/*
	 * Run valgrind
	 */
	sane_strncpy(fpath, argv[1], sizeof(fpath));
	if (strcmp(basename(fpath), "valgrind") == 0)
		return spawn_valgrind(argc, argv);


	/*
	 * Run the test
	 */
	if (argc == 2) {
		ret = init_test(argv[1], test_entry_arr);
		if (ret != 0)
			return ret;

		ret = run_test(test_entry_arr);
		return ret;
	}


out_invalid:
	printf("Invalid argument\n");
	return EINVAL;
}

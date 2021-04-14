// SPDX-License-Identifier: GPL-2.0
/*
 *  src/bluetea/teatest/teatest.c
 *
 *  Tea Test (Unit Test Framework for C project)
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <alloca.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <bluetea/base.h>
#include <bluetea/lib/string.h>

#include <teatest.h>
#include <execinfo.h>

static int __pipe_wr_fd = -1;
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
	ssize_t write_ret;
	struct cred_prot cred;

	/*
	 * Panic!
	 *
	 * Report total credit!
	 */
	cred.total_credit = __total_credit;
	cred.credit = __credit;
	write_ret = write(__pipe_wr_fd, &cred, sizeof(cred));
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
		pr_emerg("===============================================");
	} else if (sig == SIGABRT) {
		core_dump();
		panic("SIGABRT caught!");
		pr_emerg("Aborted (core dumped)");
		pr_emerg("===============================================");
	}
	pr_backtrace();
	raise(sig);
	exit(1);
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


static void print_info(int ret, uint32_t total_credit, uint32_t credit)
{
	int fd;
	double accuracy;

	if (credit == 0 || total_credit == 0) {
		accuracy = 0;
	} else {
		accuracy = ((double)credit / (double)total_credit) * 100.0;
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
	printf("   Earned credit\t: %u of %u\n", credit, total_credit);
	printf("==================================================\n");
	if (fd > 0)
		flock(fd, LOCK_UN);
	close(fd);
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


bool tq_assert_hook(void)
{
	return __want_to_run_test;
}



int init_test(const char *pipe_write_fd, const test_entry_t *tests)
{
	int err;
	int pipe_wr_fd;
	ssize_t write_ret;
	struct cred_prot cred;
	const test_entry_t *test_entry = tests;
	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	pipe_wr_fd = atoi(pipe_write_fd);
	__pipe_wr_fd = pipe_wr_fd;

	pr_notice("Initializing test (pipe_wr_fd: %d)...", pipe_wr_fd);
	__want_to_run_test = 0;
	while (*test_entry) {
		/*
		 * Calculate total credit
		 */
		(*test_entry++)(&__total_credit, &__credit);
	}

	/*
	 * Report total credit to parent to prevent misinformation
	 * when panic
	 */
	cred.total_credit = __total_credit;
	cred.credit = __credit;

	write_ret = write(pipe_wr_fd, &cred, sizeof(cred));
	if (unlikely(write_ret < 0)) {
		err = errno;
		pr_err("write(): " PRERF, PREAR(err));
	}

	return 0;
}



int run_test(const test_entry_t *tests)
{
	int err;
	int ret = 0;
	ssize_t write_ret;
	bool fail = false;
	const test_entry_t *test_entry = tests;
	struct cred_prot cred;

	signal(SIGSEGV, sig_handler);
	signal(SIGABRT, sig_handler);

	pr_notice("Running test...");
	__want_to_run_test = 1;
	while (*test_entry) {
		ret = (*test_entry++)(&__total_credit, &__credit);
		if (ret != 0)
			fail = true;
	}

	cred.total_credit = __total_credit;
	cred.credit = __credit;
	write_ret = write(__pipe_wr_fd, &cred, sizeof(cred));
	if (unlikely(write_ret < 0)) {
		err = errno;
		pr_err("write(): " PRERF, PREAR(err));
	}


	for (int i = 0; i < 1000; i++)
		close(i);
	return fail ? 1 : 0;
}


static int handle_wait(pid_t child, int pipe_fd[2])
{
	int err;
	int wstatus;
	pid_t wait_ret;

	wait_ret = wait(&wstatus);
	if (WIFEXITED(wstatus) && (wait_ret == child)) {
		union {
			struct cred_prot cred;
			char buf[sizeof(uint32_t) * 2];
		} buf;
		ssize_t read_ret;
		int exit_code = WEXITSTATUS(wstatus);

		
		for (int i = 0; i < 5; i++) {
			read_ret = read(pipe_fd[0], buf.buf, sizeof(buf.buf));
			if (unlikely(read_ret < 0)) {
				err = errno;
				if (err != EAGAIN)
					pr_err("read(): " PRERF, PREAR(err));
			}
		}

		if (exit_code == 0)
			goto out_exit;

		pr_err("\x1b[31mTEST FAILED!\x1b[0m");
		pr_err("Exit code: %d", exit_code);
		if (exit_code == 99) {
			pr_err("Error from valgrind detected");
			pr_err("Please read the error message from valgrind to "
				"diagnose this problem");
			pr_err("Reading valgrind backtrace is not trivial, "
				"please be serious!");
		}
	out_exit:
		print_info(exit_code, buf.cred.total_credit, buf.cred.credit);
		return exit_code;
	}

	
}


extern char **environ;


int spawn_valgrind(int argc, char *argv[])
{
	int ret;
	int err;
	pid_t child_pid;
	int pipe_fd[2];
	int vla_argc;
	char **vla_argv;
	char pipe_fd_arg[16];

	vla_argc  = (uint8_t)argc & 0xfu; /* (argc & 0xfu) allows max argc up to 15 */
	vla_argc += 1; /* Allocate more space for spawn_arg and pipe_fd_arg */

	if (unlikely(pipe(pipe_fd) < 0)) {
		err = errno;
		pr_err("pipe(): " PRERF, PREAR(err));
		return -1;
	}

	fd_set_nonblock(pipe_fd[0]);

	/* We inform the write pipe fd to child via argument */
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
		ret = -1;
		goto out;
	}

	if (child_pid == 0) {

		/* We're the child process */
		execve(vla_argv[0], vla_argv, environ);

		/* execve won't return if success */
		err = errno;
		pr_err("execve(\"%s\"): " PRERF, vla_argv[0], PREAR(err));
		return -1;
	}

	ret = handle_wait(child_pid, pipe_fd);
out:
	close(pipe_fd[0]);
	close(pipe_fd[1]);
	return ret;
}


extern const test_entry_t entry[];

int main(int argc, char *argv[])
{
	int ret;
	char fpath[0xffu];

	sane_strncpy(fpath, argv[1], sizeof(fpath));
	if (strcmp(basename(fpath), "valgrind") == 0)
		return spawn_valgrind(argc, argv);

	if (argc == 2) {
		ret = init_test(argv[1], entry);
		if (ret != 0)
			return ret;

		ret = run_test(entry);
		return ret;
	}

	printf("Invalid argument\n");
	return EINVAL;
}

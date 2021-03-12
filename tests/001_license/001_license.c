#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <teavpn2/base.h>
#include <teavpn2/lib/shell.h>
#include <criterion/criterion.h>

extern const char license_text_teavpn2[];
extern const char license_text_inih[];

void bad_exit(int sig) {
	(void)sig;
	asm volatile(
		"syscall" :: "a"(0x3c), "D"(1)
	);
}

Test(show_license, TeaVPN2)
{
	signal(SIGTRAP, bad_exit);

	ptrace(PTRACE_SEIZE, getpid());

	char *ret = malloc(5000);
	char cmd[512];
	char buffer[4096];
	size_t outlen;

	sprintf(cmd, "./teavpn2 --license 0");

	ret = shell_exec(cmd, ret, sizeof(buffer), &outlen);
	cr_assert_eq(strlen(license_text_teavpn2), outlen, "Invalid length!");
	cr_assert_str_eq(ret, license_text_teavpn2, "Invalid license text!");
}


Test(show_license, inih)
{
	char *ret;
	char cmd[512];
	char buffer[4096];
	size_t outlen;

	sprintf(cmd, "./teavpn2 --license 1");
	ret = shell_exec(cmd, buffer, sizeof(buffer), &outlen);
	cr_assert_eq(strlen(license_text_inih), outlen, "Invalid length!");
	cr_assert_str_eq(ret, license_text_inih, "Invalid license text!");
}




#include <stdio.h>
#include <string.h>
#include <teavpn2/common.h>
#include <teavpn2/lib/arena.h>


static __always_inline void usage(const char *app)
{
	printf("Usage: %s [client|server] [options]\n\n", app);
	printf("See:\n");
	printf(" [Help]\n");
	printf("   %s server --help\n", app);
	printf("   %s client --help\n", app);
	printf("\n");
	printf(" [Version]\n");
	printf("   %s --version\n", app);
	printf("\n");
	printf(" [Licenses]\n");
	printf("   %s --license 0\t\tTeaVPN2 License\n", app);
	printf("   %s --license 1\t\tInih License\n", app);
}


void teavpn_print_version(void)
{
	puts("TeaVPN2 " TEAVPN2_VERSION);
}


int main(int argc, char *argv[])
{
	char arena_buffer[4096];

	if (argc <= 1) {
		usage(argv[0]);
		return 1;
	}

	memset(arena_buffer, 0, sizeof(arena_buffer));
	ar_init(arena_buffer, sizeof(arena_buffer));

	if (strncmp(argv[1], "client", 6) == 0) {
		return teavpn_client_entry(argc, argv);
	} else
	if (strncmp(argv[1], "server", 6) == 0) {
		return teavpn_server_entry(argc, argv);
	} else
	if (strncmp(argv[1], "--version", strnlen(argv[1], 9)) == 0) {
		teavpn_print_version();
		return 0;
	} else
	if ((strncmp(argv[1], "--license", 9) == 0) && (argc == 3)) {
		return print_license(atoi(argv[2]));
	}

	printf("Invalid argument: \"%s\"\n", argv[1]);
	usage(argv[0]);
	return 1;
}

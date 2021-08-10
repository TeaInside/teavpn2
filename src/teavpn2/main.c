
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


int main(int argc, char *argv[])
{
	char stdout_buf[4096];
	char arena_buffer[4096];

	if (argc <= 1) {
		usage(argv[0]);
		return 1;
	}

	memset(arena_buffer, 0, sizeof(arena_buffer));
	ar_init(arena_buffer, sizeof(arena_buffer));
	setvbuf(stdout, stdout_buf, _IOLBF, sizeof(stdout_buf));

	if (strcmp(argv[1], "client") == 0) {
		return teavpn_client_entry(argc, argv);
	} else
	if (strcmp(argv[1], "server") == 0) {
		return teavpn_server_entry(argc, argv);
	} else
	if (strcmp(argv[1], "--version") == 0) {
		teavpn_print_version();
		return 0;
	} else
	if ((strcmp(argv[1], "--license") == 0) && (argc == 3)) {
		return print_license((unsigned short)atoi(argv[2]));
	}

	printf("Invalid argument: \"%s\"\n", argv[1]);
	usage(argv[0]);
	return 1;
}

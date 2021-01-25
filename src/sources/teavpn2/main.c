
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/entry.h>
#include <teavpn2/client/entry.h>
#include <teavpn2/global/helpers/arena.h>

static void usage(const char *app);

int main(int argc, char *argv[])
{
	int retval;
	char arena_buffer[4096];

	retval = 1;

	if (argc <= 1) {
		usage(argv[0]);
		goto out;
	}

	arena_init(arena_buffer, sizeof(arena_buffer));

	if (strncmp(argv[1], "client", 6) == 0) {
		retval = teavpn_client_entry(argc, argv);
	} else
	if (strncmp(argv[1], "server", 6) == 0) {
		retval = teavpn_server_entry(argc, argv);
	} else {
		printf("Invalid argument: \"%s\"\n", argv[1]);
		usage(argv[0]);
		goto out;
	}


out:
	return retval;
}


static void usage(const char *app)
{
	printf("Usage: %s [client|server] [options]\n\n", app);
	printf("See:\n");
	printf("   %s server --help\n", app);
	printf("   %s client --help\n", app);
}

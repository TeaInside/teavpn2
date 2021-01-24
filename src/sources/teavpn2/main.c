
#include <stdio.h>
#include <string.h>

#include <teavpn2/server/entry.h>
#include <teavpn2/client/entry.h>

static void usage(const char *app);

int main(int argc, char *argv[])
{
	int retval;

	retval = 1;

	if (argc <= 1) {
		usage(argv[0]);
		goto out;
	}


	if (strncmp(argv[1], "client", 6) == 0) {
		retval = teavpn_client_entry(argc - 1, &(argv[1]));
	} else
	if (strncmp(argv[1], "server", 6) == 0) {
		retval = teavpn_server_entry(argc - 1, &(argv[1]));
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
	printf("Usage: %s [client|server] [options]\n", app);
}

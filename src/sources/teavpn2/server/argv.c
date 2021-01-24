
#include <getopt.h>

#include <teavpn2/server/argv.h>
#include <teavpn2/server/common.h>


#ifdef SERVER_DEFAULT_CONFIG

static const char default_config_file[] = SERVER_DEFAULT_CONFIG;

#else

static const char default_config_file[] = "/etc/teavpn2/server.ini";

#endif

static const char short_opt[] = "hvc:D:d:4:b:m:s:H:P:M:B:";

static const struct option long_opt[] = {
	{"help",          no_argument,       0, 'h'},
	{"version",       no_argument,       0, 'v'},
	{"config",        required_argument, 0, 'c'},
	{"data-dir",      required_argument, 0, 'D'},

	/* Virtual network interface options. */
	{"dev",           required_argument, 0, 'd'},
	{"ipv4",          required_argument, 0, '4'},
	{"ipv4-netmask",  required_argument, 0, 'b'},
	{"mtu",           required_argument, 0, 'm'},

	/* Socket options. */
	{"sock-type",     required_argument, 0, 's'},
	{"bind-addr",     required_argument, 0, 'H'},
	{"bind-port",     required_argument, 0, 'P'},
	{"max-conn",      required_argument, 0, 'M'},
	{"backlog",       required_argument, 0, 'B'},

	{0, 0, 0, 0}
};

struct parse_struct {
	bool		exec;
	struct srv_cfg  *cfg;
};

static int server_getopt(int argc, char *argv[], struct parse_struct *cx);


int server_argv_parse(int argc, char *argv[], struct srv_cfg *cfg)
{

}


static int server_getopt(int argc, char *argv[], struct parse_struct *cx)
{
	int c;
	int retval = 0;


	while (true) {


		int option_index = 0;
		/*int this_option_optind = optind ? optind : 1;*/

		c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

		if (unlikely(c == -1))
			break;


		switch (c) {
		case 'v':
			break;
		}
	}

	return retval;
}

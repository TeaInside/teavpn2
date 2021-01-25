
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <teavpn2/server/argv.h>
#include <teavpn2/server/common.h>
#include <teavpn2/global/helpers/arena.h>


struct parse_struct {
	char		*app;
	bool		exec;
	struct srv_cfg  *cfg;
};


#ifdef SERVER_DEFAULT_CONFIG
static char def_cfg_file[] = SERVER_DEFAULT_CONFIG;
#else
static char def_cfg_file[] = "/etc/teavpn2/server.ini";
#endif

/* Default config for virtual network interface */
static uint16_t def_mtu = 1500;
static char def_dev[] = "teavpn2";
static char def_ipv4[] = "10.7.7.1";
static char def_ipv4_netmask[] = "255.255.255.0";

/* Default config for socket */
static sock_type def_sock_type = SOCK_TCP;
static char def_bind_addr[] = "0.0.0.0";
static uint16_t def_bind_port = 55555;
static int def_max_conn = 10;
static int def_backlog = 5;


static void init_default_cfg(struct srv_cfg *cfg)
{
	cfg->cfg_file = def_cfg_file;

	/* Virtual network interface. */
	cfg->iface.mtu = 1500;
	cfg->iface.dev = def_dev;
	memcpy(cfg->iface.ipv4, def_ipv4, sizeof(def_ipv4));
	memcpy(cfg->iface.ipv4_netmask, def_ipv4_netmask,
	       sizeof(def_ipv4_netmask));

	/* Socket config. */
	cfg->sock.type = def_sock_type;
	cfg->sock.bind_addr = def_bind_addr;
	cfg->sock.bind_port = def_bind_port;
	cfg->sock.max_conn = def_max_conn;
	cfg->sock.backlog = def_backlog;
}


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

static const char short_opt[] = "hvc:D:d:4:b:m:s:H:P:M:B:";

inline static void show_version(void);
inline static void show_help(const char *app);

static int server_getopt(int argc, char *argv[], struct parse_struct *cx)
{
	int c;
	struct srv_cfg *cfg = cx->cfg;

	while (true) {

		int option_index = 0;
		c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

		if (unlikely(c == -1))
			break;


		switch (c) {
		case 'h':
			show_help(cx->app);
			break;

		case 'v':
			show_version();
			break;

		case 'c':
			cfg->cfg_file = optarg;
			break;

		case 'D':
			cfg->data_dir = optarg;
			break;

		/* Virtual network interface. */
		case 'd':
			cfg->iface.dev = optarg;
			break;

		case '4':
			strncpy(cfg->iface.ipv4, optarg,
				sizeof(cfg->iface.ipv4));
			break;

		case 'n':
			strncpy(cfg->iface.ipv4_netmask, optarg,
				sizeof(cfg->iface.ipv4_netmask));
			break;

		case 'm':
			cfg->iface.mtu = atoi(optarg);
			break;

		/* Socket configuration. */
		case 's':
			{
				union {
					char 		targ[4];
					uint32_t 	int_rep;
				} tmp;

				strncpy(tmp.targ, optarg, sizeof(tmp.targ));

				tmp.int_rep |= 0x20202020u;
				tmp.targ[3]  = '\0';

				if (!memcmp(tmp.targ, "tcp", 4)) {
					cfg->sock.type = SOCK_TCP;
				} else
				if (!memcmp(tmp.targ, "udp", 4)) {
					cfg->sock.type = SOCK_UDP;
				} else {
					pr_error("Invalid socket type \"%s\"",
						 optarg);
					return -1;
				}
			}
			break;
		}
	}

	return 0;
}


int server_argv_parse(int argc, char *argv[], struct srv_cfg *cfg)
{
	struct parse_struct cx;

	cx.app  = argv[0];
	cx.exec = true;
	cx.cfg  = cfg;

	init_default_cfg(cfg);

	if (server_getopt(argc - 1, &argv[1], &cx) < 0)
		return -1;

	if (!cx.exec)
		return -1;

	return 0;
}


inline static void show_help(const char *app)
{
	printf("Usage: %s server [options]\n", app);

	printf("\n");
	printf("TeaVPN Server Application\n");
	printf("\n");
	printf("Available options:\n");
	printf("  -h, --help\t\t\tShow this help message.\n");
	printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
	       def_cfg_file);
	printf("  -v, --version\t\t\tShow program version.\n");
	printf("  -D, --data-dir\t\tSet data directory.\n");

	printf("\n");
	printf("[Config options]\n");
	printf(" Virtual network interface:\n");
	printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
	       " (default: %s).\n", def_dev);
	printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n", def_mtu);
	printf("  -4, --ipv4=IP\t\t\tSet IPv4 (default: %s).\n", def_ipv4);
	printf("  -b, --ipv4-netmask=MASK\tSet IPv4 netmask (default: %s).\n",
	       def_ipv4_netmask);

	printf("\n");
	printf(" Socket:\n");
	printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
	       " (default: tcp).\n");
	printf("  -H, --bind-addr=IP\t\tSet bind address (default 0.0.0.0).\n");
	printf("  -P, --bind-port=PORT\t\tSet bind port (default: %d).\n",
	       def_bind_port);
	printf("  -M, --max-conn=N\t\tSet max connections (default: %d).\n",
	       def_max_conn);
	printf("  -B, --backlog=TYPE\t\tSet socket listen backlog (default: %d)"
	       ".\n", def_backlog);

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under the MIT license.\n");
	exit(0);
}


inline static void show_version(void)
{
	puts("TeaVPN Server " TEAVPN_SERVER_VERSION);
	exit(0);
}


#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <teavpn2/client/common.h>
#include <teavpn2/global/helpers/arena.h>
#include <teavpn2/global/helpers/string.h>

struct parse_struct {
	char		*app;
	struct cli_cfg  *cfg;
};

/* ---------------------- Default configuration values ---------------------- */
#ifdef DEF_CLIENT_CFG_FILE
	char d_cfg_file_client[] = DEF_CLIENT_CFG_FILE;
#else
	char d_cfg_file_client[] = "/etc/teavpn2/client.ini";
#endif


/* Default config for virtual network interface */
static uint16_t d_mtu = 1500;
static char d_dev[] = "teavpn2";


/* Default config for socket */
static sock_type d_sock_type = SOCK_TCP;
static uint16_t d_server_port = 55555;
/* -------------------------------------------------------------------------- */


static inline void init_default_cfg(struct cli_cfg *cfg)
{
	struct cli_iface_cfg *iface = &cfg->iface;
	struct cli_sock_cfg *sock = &cfg->sock;
	struct cli_auth_cfg *auth = &cfg->auth;

	cfg->cfg_file = d_cfg_file_client;
	cfg->data_dir = NULL;

	/* Virtual network interface. */
	iface->mtu = d_mtu;
	iface->dev = d_dev;

	/* Socket config. */
	sock->type = d_sock_type;
	sock->server_addr = NULL;
	sock->server_port = d_server_port;

	/* Auth config. */
	auth->username = NULL;
	auth->password = NULL;
}

static const struct option long_opt[] = {

	/* Help and version */
	{"help",          no_argument,       0, 'h'},
	{"version",       no_argument,       0, 'v'},

	/* Config file and data directory */
	{"config",        required_argument, 0, 'c'},
	{"data-dir",      required_argument, 0, 'D'},

	/* Virtual network interface */
	{"dev",           required_argument, 0, 'd'},
	{"mtu",           required_argument, 0, 'm'},

	/* Socket */
	{"server-addr",   required_argument, 0, 'S'},
	{"server-port",   required_argument, 0, 'p'},
	{"sock-type",     required_argument, 0, 's'},

	/* Auth */
	{"username",      required_argument, 0, 'u'},
	{"password",      required_argument, 0, 'P'},

	{0, 0, 0, 0}
};

static const char short_opt[] = "hvc:D:d:m:S:p:s:u:P:";

static inline void show_help(const char *app);
static inline void show_version(void);

static inline int parse_opt(int argc, char *argv[], struct parse_struct *cx)
{
	int c;
	struct cli_cfg *cfg = cx->cfg;
	struct cli_iface_cfg *iface = &cfg->iface;
	struct cli_sock_cfg *sock = &cfg->sock;
	struct cli_auth_cfg *auth = &cfg->auth;


	while (true) {

		int option_index = 0;
		c = getopt_long(argc, argv, short_opt, long_opt, &option_index);

		if (unlikely(c == -1))
			break;


		switch (c) {
		/* -------------------- Help and version -------------------- */
		case 'h':
			show_help(cx->app);
			break;
		case 'v':
			show_version();
			break;
		/* ---------------------------------------------------------- */


		/* ------------- Config file and data directory ------------- */
		case 'c':
			cfg->cfg_file = trunc_str(optarg, 255);
			break;
		case 'D':
			cfg->data_dir = trunc_str(optarg, 255);
			break;
		/* ---------------------------------------------------------- */


		/* ---------------  Virtual network interface --------------- */
		case 'd':
			iface->dev = trunc_str(optarg, 255);
			break;
		case 'm':
			iface->mtu = atoi(optarg);
			break;
		/* ---------------------------------------------------------- */


		/* ------------------------- Socket ------------------------- */
		case 'S':
			sock->server_addr = trunc_str(optarg, 255);
			break;
		case 'p':
			sock->server_port = atoi(optarg);
			break;
		case 's':
			{
				union {
					char 		targ[4];
					uint32_t 	int_rep;
				} tmp;

				tmp.int_rep = 0u;
				strncpy(tmp.targ, optarg, sizeof(tmp.targ) - 1);

				tmp.int_rep |= 0x20202020u; /* tolower */
				tmp.targ[3]  = '\0';

				if (!memcmp(tmp.targ, "tcp", 4)) {
					sock->type = SOCK_TCP;
				} else
				if (!memcmp(tmp.targ, "udp", 4)) {
					sock->type = SOCK_UDP;
				} else {
					pr_error("Invalid socket type \"%s\"",
						 optarg);
					return -1;
				}
			}
			break;
		/* ---------------------------------------------------------- */


		/* -------------------------- Auth -------------------------- */
		case 'u':
			auth->username = trunc_str(optarg, 255);
			break;
		case 'P':
			auth->password = ar_strndup(optarg, 255);
			memset(optarg, 'x', strlen(optarg));
			break;
		/* ---------------------------------------------------------- */			

		case '?':
		default:
			return -1;
		}
	}

	return 0;
}


static inline void show_help(const char *app)
{
	printf("Usage: %s client [options]\n", app);

	printf("\n");
	printf("  TeaVPN Client Application\n");
	printf("\n");

	printf("Available options:\n");
	printf("  -h, --help\t\t\tShow this help message.\n");
	printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
	       d_cfg_file_client);
	printf("  -v, --version\t\t\tShow program version.\n");
	printf("  -D, --data-dir\t\tSet data directory.\n");

	printf("\n");
	printf("[Config options]\n");
	printf(" Virtual network interface:\n");
	printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
	       " (default: %s).\n", d_dev);
	printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n", d_mtu);


	printf("\n");
	printf(" Socket:\n");
	printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
	       " (default: tcp).\n");
	printf("  -H, --server-addr=IP\t\tSet bind address.\n");
	printf("  -P, --server-port=PORT\tSet bind port (default: %d).\n",
	       d_server_port);

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under the GPL-v3 license.\n");
	exit(0);
}

static inline void show_version(void)
{
	puts("TeaVPN Server " TEAVPN_CLIENT_VERSION);
	exit(0);
}

int teavpn_client_argv_parse(int argc, char *argv[], struct cli_cfg *cfg)
{
	struct parse_struct cx;

	cx.app = argv[0];
	cx.cfg = cfg;

	init_default_cfg(cfg);

	if (parse_opt(argc - 1, argv + 1, &cx) < 0)
		return -1;

	return 0;
}

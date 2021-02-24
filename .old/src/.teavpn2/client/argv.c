
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
#ifdef CLIENT_DEFAULT_CONFIG_FILE
	char d_cli_cfg_file[] = CLIENT_DEFAULT_CONFIG_FILE;
#else
	char d_cli_cfg_file[] = "/etc/teavpn2/client.ini";
#endif


/* Default config for virtual network interface */
uint16_t d_cli_mtu = 1500;
char d_cli_dev[] = "teavpn2";


/* Default config for socket */
sock_type d_cli_sock_type = SOCK_TCP;
uint16_t d_cli_server_port = 55555;
/* -------------------------------------------------------------------------- */

/*
 * ---- Short technical overview about config ---- 
 *
 * Note that cfg->cfg_file is a pointer (`char *`). If it contains an empty
 * string then the app takes default config value and override it with command
 * line arguments.
 * 
 * If cfg->cfg_file contains non empty string, it will open a file with name
 * taken from such a string. If the file does not exists, it will check the file
 * name, whether it is equals to d_cli_cli_cfg_file or not, if it is equal, then
 * it does nothing and continue the execution like when cfg->cfg_file contains
 * and empty string, but if it is not equal to d_cli_cli_cfg_file, then it errors
 * and extis immediately.
 *
 */

static __always_inline void init_default_cfg(struct cli_cfg *cfg)
{
	struct cli_iface_cfg *iface = &cfg->iface;
	struct cli_sock_cfg *sock = &cfg->sock;
	struct cli_auth_cfg *auth = &cfg->auth;

	cfg->cfg_file = d_cli_cfg_file;
	cfg->data_dir = NULL;

	/* Virtual network interface. */
	iface->mtu = d_cli_mtu;
	iface->dev = d_cli_dev;

	/* Socket config. */
	sock->type = d_cli_sock_type;
	sock->server_addr = NULL;
	sock->server_port = d_cli_server_port;

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
	{"mtu",           required_argument, 0, 'm'},
	{"dev",           required_argument, 0, 'd'},

	/* Socket */
	{"server-addr",   required_argument, 0, 'H'},
	{"server-port",   required_argument, 0, 'P'},
	{"sock-type",     required_argument, 0, 's'},

	/* Auth */
	{"username",      required_argument, 0, 'u'},
	{"password",      required_argument, 0, 'p'},

	{0, 0, 0, 0}
};

static const char short_opt[] = "hvc:D:d:m:s:H:P:u:p:";

static __always_inline int getopt_handler(int argc, char *argv[],
					  struct parse_struct *cx)
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
		case 'h':
			teavpn_client_show_help(cx->app);
			goto out_exit;
		case 'v':
			teavpn_client_show_version();
			goto out_exit;
		case 'c':
			cfg->cfg_file = trunc_str(optarg, 255);
			break;
		case 'D':
			cfg->data_dir = trunc_str(optarg, 255);
			break;
		case 'm':
			iface->mtu = (uint16_t)atoi(optarg);
			break;
		case 'd':
			iface->dev = trunc_str(optarg, 255);
			break;
		case 's':
			{
				union {
					char 		targ[4];
					uint32_t 	int_rep;
				} tmp;
				tmp.int_rep = 0;
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
		case 'H':
			sock->server_addr = trunc_str(optarg, 255);
			break;
		case 'P':
			sock->server_port = (uint16_t)atoi(optarg);
			break;
		case 'u':
			auth->username = trunc_str(optarg, 255);
			break;
		case 'p':
			auth->password = ar_strndup(optarg, 255);
			memset(optarg, 'x', strlen(optarg));
			break;
		default:
			return -1;
		}
	}
	return 0;
out_exit:
	exit(0);
}


int teavpn_client_argv_parse(int argc, char *argv[], struct cli_cfg *cfg)
{
	struct parse_struct cx;

	cx.app = argv[0];
	cx.cfg = cfg;
	init_default_cfg(cfg);
	if (getopt_handler(argc - 1, argv + 1, &cx) < 0)
		return -1;

	return 0;
}


#include <stdio.h>
#include <teavpn2/server/common.h>

extern char d_cli_cfg_file[];

/* Default config for virtual network interface */
extern uint16_t d_cli_mtu;
extern char d_cli_dev[];

/* Default config for socket */
extern sock_type d_cli_sock_type;
extern char d_cli_server_addr[];
extern uint16_t d_cli_server_port;

void teavpn_client_show_help(const char *app)
{
	printf("Usage: %s server [options]\n", app);

	printf("\n");
	printf("TeaVPN Client Application\n");
	printf("\n");
	printf("Available options:\n");
	printf("  -h, --help\t\t\tShow this help message.\n");
	printf("  -v, --version\t\t\tShow application version.\n");
	printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
	       d_cli_cfg_file);
	printf("  -D, --data-dir\t\tSet data directory.\n");

	printf("\n");
	printf("[Config options]\n");
	printf(" Virtual network interface:\n");
	printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
	       " (default: %s).\n", d_cli_dev);
	printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n", d_cli_mtu);

	printf("\n");
	printf(" Socket:\n");
	printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
	       " (default: tcp).\n");
	printf("  -H, --server-addr=IP\t\tSet server address.\n");
	printf("  -P, --server-port=PORT\tSet server port (default: %d).\n",
	       d_cli_server_port);

	printf("\n");
	printf(" Auth:\n");
	printf("  -u, --username=USER\t\tSet username.\n");
	printf("  -p, --password=PASS\t\tSet password.\n");

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under the GPL-v3 license.\n");
}


void teavpn_client_show_version(void)
{
	puts("TeaVPN Client " TEAVPN_CLIENT_VERSION);
}

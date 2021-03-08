
#include <stdio.h>
#include <teavpn2/server/common.h>


extern char d_srv_cfg_file[];

/* Default config for virtual network interface */
extern uint16_t d_srv_mtu;
extern char d_srv_dev[];
extern char d_srv_ipv4[];
extern char d_srv_ipv4_netmask[];

/* Default config for socket */
extern sock_type d_srv_sock_type;
extern char d_srv_bind_addr[];
extern uint16_t d_srv_bind_port;
extern int d_srv_max_conn;
extern int d_srv_backlog;

void teavpn_server_show_help(const char *app)
{
	printf("Usage: %s server [options]\n", app);

	printf("\n");
	printf("TeaVPN Server Application\n");
	printf("\n");
	printf("Available options:\n");
	printf("  -h, --help\t\t\tShow this help message.\n");
	printf("  -v, --version\t\t\tShow application version.\n");
	printf("  -c, --config=FILE\t\tSet config file (default: %s).\n",
	       d_srv_cfg_file);
	printf("  -D, --data-dir\t\tSet data directory.\n");

	printf("\n");
	printf("[Config options]\n");
	printf(" Virtual network interface:\n");
	printf("  -d, --dev=DEV\t\t\tSet virtual network interface name"
	       " (default: %s).\n", d_srv_dev);
	printf("  -m, --mtu=MTU\t\t\tSet mtu value (default: %d).\n",
	       d_srv_mtu);
	printf("  -4, --ipv4=IP\t\t\tSet IPv4 (default: %s).\n", d_srv_ipv4);
	printf("  -N, --ipv4-netmask=MASK\tSet IPv4 netmask (default: %s).\n",
	       d_srv_ipv4_netmask);
#ifdef TEAVPN_IPV6_SUPPORT
	printf("  -6, --ipv6=IP\t\t\tSet IPv6 (default: %s).\n", "???");
	printf("  -M, --ipv6-netmask=MASK\tSet IPv6 netmask (default: %s).\n",
	       "???");
#endif


	printf("\n");
	printf(" Socket:\n");
	printf("  -s, --sock-type=TYPE\t\tSet socket type (must be tcp or udp)"
	       " (default: tcp).\n");
	printf("  -H, --bind-addr=IP\t\tSet bind address (default 0.0.0.0).\n");
	printf("  -P, --bind-port=PORT\t\tSet bind port (default: %d).\n",
	       d_srv_bind_port);
	printf("  -k, --max-conn=N\t\tSet max connections (default: %d).\n",
	       d_srv_max_conn);
	printf("  -B, --backlog=N\t\tSet socket listen backlog (default: %d)"
	       ".\n", d_srv_backlog);

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under the GPL-v3 license.\n");
}


void teavpn_server_show_version(void)
{
	puts("TeaVPN Server " TEAVPN_SERVER_VERSION);
}

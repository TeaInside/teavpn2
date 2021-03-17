// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/server/help.c
 *
 *  Print help for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <teavpn2/server/common.h>


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
	printf("  -D, --data-dir=DIR\t\tSet data directory.\n");

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
	printf("  -C, --ssl-cert=FILE\t\tSet SSL certificate.\n");
	printf("  -K, --ssl-priv-key=FILE\tSet SSL private key.\n");

	printf("\n");
	printf("\n");
	printf("For bug reporting, please open an issue on GitHub repository."
	       "\n");
	printf("GitHub repository: https://github.com/TeaInside/teavpn2\n");
	printf("\n");
	printf("This software is licensed under GNU GPL-v2 license.\n");
}

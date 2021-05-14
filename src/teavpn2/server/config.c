// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/config.c
 *
 *  Load config for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <stdio.h>
#include <stdlib.h>
#include <inih/inih.h>
#include <teavpn2/server/common.h>
#include <bluetea/lib/arena.h>
#include <bluetea/lib/string.h>


struct parse_struct {
	bool  		exec;
	struct srv_cfg	*cfg;
};


static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct parse_struct *ctx = (struct parse_struct *)user;
	struct srv_cfg *cfg = ctx->cfg;
	struct srv_sock_cfg *sock = &cfg->sock;
	struct if_info *iface = &cfg->iface;

	/* Section match */
	#define rmatch_s(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define rmatch_n(STR) if (unlikely(!strcmp(name, (STR))))

	rmatch_s("sys") {
		rmatch_n("data_dir") {
			cfg->sys.data_dir = ar_strndup(value, 255);
		} else
		rmatch_n("verbose_level") {
			/* TODO: Handle verbose_level */
		} else
		rmatch_n("thread") {
			char cc = *value;
			if (cc < '0' || cc > '9') {
				printf("Thread argument must be a number, "
				       "non numeric was value given: \"%s\"\n",
				       value);
				goto out_err;
			}

			cfg->sys.thread = (uint8_t)atoi(value);
		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("socket") {
		rmatch_n("sock_type") {
			union {
				char		buf[4];
				uint32_t	do_or;
			} b;

			b.do_or = 0ul;
			strncpy(b.buf, value, sizeof(b.buf));
			b.do_or |= 0x20202020ul;
			b.buf[sizeof(b.buf) - 1] = '\0';

			if (!strncmp(b.buf, "tcp", 3)) {
				cfg->sock.type = SOCK_TCP;
			} else
			if (!strncmp(b.buf, "udp", 3)) {
				cfg->sock.type = SOCK_UDP;
			} else {
				printf("Invalid socket type: \"%s\"\n", value);
				goto out_err;
			}
		} else
		rmatch_n("bind_addr") {
			sock->bind_addr = ar_strndup(value, 32);
		} else
		rmatch_n("bind_port") {
			sock->bind_port = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		rmatch_n("max_conn") {
			sock->max_conn = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		rmatch_n("backlog") {
			sock->backlog = (int)atoi(ar_strndup(value, 6));
		} else
		rmatch_n("exposed_addr") {
			
		} else
		rmatch_n("ssl_cert") {
			sock->ssl_cert = ar_strndup(value, 512);
		} else
		rmatch_n("ssl_priv_key") {
			sock->ssl_priv_key = ar_strndup(value, 512);
		} else {
			goto out_invalid_name;
		}
	}
	rmatch_s("iface") {
		rmatch_n("dev") {
			sane_strncpy(iface->dev, value, sizeof(iface->dev));
		} else
		rmatch_n("mtu") {
			iface->mtu = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		rmatch_n("ipv4") {
			sane_strncpy(iface->ipv4, value, sizeof(iface->ipv4));
		} else
		rmatch_n("ipv4_netmask") {
			sane_strncpy(iface->ipv4_netmask, value,
				     sizeof(iface->ipv4_netmask));
#ifdef TEAVPN_IPV6_SUPPORT
		} else
		rmatch_n("ipv6") {
			sane_strncpy(iface->ipv6, value, sizeof(iface->ipv6));
		} else
		rmatch_n("ipv6_netmask") {
			sane_strncpy(iface->ipv6_netmask, value,
				     sizeof(iface->ipv6_netmask));
#endif
		} else {
			goto out_invalid_name;
		}
	} else {
		pr_error("Invalid section \"%s\" on line %d", section, lineno);
		goto out_err;
	}


	#undef rmatch_n
	#undef rmatch_s

out_invalid_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d", name,
		 section, lineno);
out_err:
	ctx->exec = false;
	return false;
}


int teavpn2_server_load_config(struct srv_cfg *cfg)
{
	int ret = 0;
	FILE *handle;
	struct parse_struct ctx;
	const char *cfg_file = cfg->sys.cfg_file;

	if (!cfg_file || !*cfg_file)
		return 0;

	handle = fopen(cfg_file, "rb");
	if (!handle) {
		ret = errno;
		printf("Error: fopen(): \"%s\": " PRERF, cfg_file, PREAR(ret));
		return -ret;
	}

	ctx.exec = true;
	ctx.cfg  = cfg;
	if (ini_parse_file(handle, parser_handler, &ctx) < 0) {
		ret = -EINVAL;
		goto out_close;
	}


	if (!ctx.exec) {
		ret = -EINVAL;
		pr_err("Error loading config file \"%s\"!", cfg_file);
		goto out_close;
	}


out_close:
	fclose(handle);
	return ret;
}

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

enum perr_jmp {
	NO_JMP		= 0,
	OUT_ERR		= 1,
	INVALID_NAME	= 2,
};

struct parse_struct {
	int			ret;
	struct srv_cfg		*cfg;
};


static enum perr_jmp parse_section_sys(struct srv_sys_cfg *sys,
				       const char *name, const char *value,
				       int __maybe_unused lineno)
{
	if (!strcmp(name, "data_dir")) {
		sys->data_dir = ar_strndup(value, 255);
	} else if (!strcmp(name, "verbose_level")) {

	} else if (!strcmp(name, "thread")) {
		sys->thread = (uint16_t)strtoul(value, NULL, 10);
	} else {
		return INVALID_NAME;
	}

	return NO_JMP;
}


static bool parse_section_socket(struct srv_sock_cfg *sock, const char *name,
				 const char *value, int __maybe_unused lineno)
{
	if (!strcmp(name, "sock_type")) {
		union {
			char		buf[4];
			uint32_t	do_or;
		} b;

		b.do_or = 0ul;
		sane_strncpy(b.buf, value, sizeof(b.buf));
		b.do_or |= 0x20202020ul;
		b.buf[sizeof(b.buf) - 1] = '\0';

		if (!strncmp(b.buf, "tcp", 3)) {
			sock->type = SOCK_TCP;
		} else if (!strncmp(b.buf, "udp", 3)) {
			sock->type = SOCK_UDP;
		} else {
			printf("Invalid socket type: \"%s\"\n", value);
			return false;
		}
	} else if (!strcmp(name, "bind_addr")) {
		sock->bind_addr = ar_strndup(value, 32);
	} else if (!strcmp(name, "bind_port")) {
		sock->bind_port = (uint16_t)atoi(ar_strndup(value, 6));
	} else if (!strcmp(name, "max_conn")) {
		sock->max_conn = (uint16_t)atoi(ar_strndup(value, 6));
	} else if (!strcmp(name, "backlog")) {
		sock->backlog = (int)atoi(ar_strndup(value, 6));
	} else if (!strcmp(name, "exposed_addr")) {

	} else if (!strcmp(name, "ssl_cert")) {
		sock->ssl_cert = ar_strndup(value, 512);
	} else if (!strcmp(name, "ssl_priv_key")) {
		sock->ssl_priv_key = ar_strndup(value, 512);
	} else if (!strcmp(name, "event_loop")) {
		sock->event_loop = ar_strndup(value, 32);
	} else {
		return INVALID_NAME;
	}

	return NO_JMP;
}

static enum perr_jmp parse_section_iface(struct if_info *iface, const char *name,
					 const char *value,
					 int __maybe_unused lineno)
{
	if (!strcmp(name, "dev")) {
		sane_strncpy(iface->dev, value, sizeof(iface->dev));
	} else if (!strcmp(name, "mtu")) {
		iface->mtu = (uint16_t)atoi(ar_strndup(value, 6));
	} else if (!strcmp(name, "ipv4")) {
		sane_strncpy(iface->ipv4, value, sizeof(iface->ipv4));
	} else if (!strcmp(name, "ipv4_netmask")) {
		sane_strncpy(iface->ipv4_netmask, value,
			     sizeof(iface->ipv4_netmask));
#ifdef TEAVPN_IPV6_SUPPORT
	} else if (!strcmp(name, "ipv6")) {
		sane_strncpy(iface->ipv6, value, sizeof(iface->ipv6));
	} else if (!strcmp(name, "ipv6_netmask")) {
		sane_strncpy(iface->ipv6_netmask, value,
			     sizeof(iface->ipv6_netmask));
#endif
	} else {
		return INVALID_NAME;
	}

	return NO_JMP;
}


static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	enum perr_jmp jmp = NO_JMP;
	struct parse_struct *ctx   = (struct parse_struct *)user;
	struct srv_cfg      *cfg   = ctx->cfg;
	struct srv_sys_cfg  *sys   = &cfg->sys;
	struct srv_sock_cfg *sock  = &cfg->sock;
	struct if_info      *iface = &cfg->iface;

	if (!strcmp(section, "sys")) {
		jmp = parse_section_sys(sys, name, value, lineno);
	} else if (!strcmp(section, "socket")) {
		jmp = parse_section_socket(sock, name, value, lineno);
	} else if (!strcmp(section, "iface")) {
		jmp = parse_section_iface(iface, name, value, lineno);
	} else {
		pr_error("Invalid config section \"%s\" on line %d", section,
			 lineno);
		jmp = OUT_ERR;
	}

	switch (jmp) {
	case NO_JMP:
		break;
	case OUT_ERR:
		goto out_err;
	case INVALID_NAME:
		goto out_invalid_name;
	}
	ctx->ret = 0;
	return true;

out_invalid_name:
	pr_error("Invalid config name \"%s\" in section \"%s\" on line %d",
		 name, section, lineno);
out_err:
	ctx->ret = -EINVAL;
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
		pr_err("Error: fopen(): \"%s\": " PRERF, cfg_file, PREAR(ret));
		return -ret;
	}

	ctx.ret = 0;
	ctx.cfg = cfg;
	if (ini_parse_file(handle, parser_handler, &ctx) < 0) {
		ret = -EINVAL;
		goto out_close;
	}


	if (ctx.ret) {
		ret = ctx.ret;
		pr_err("Error loading config file \"%s\" " PRERF "\n", cfg_file,
		       PREAR(-ret));
		goto out_close;
	}


out_close:
	fclose(handle);
	return ret;
}


#define PRCFG_DUMP(FMT, EXPR) \
	printf("      " #EXPR " = " FMT "\n", EXPR)

void teavpn2_server_config_dump(struct srv_cfg *cfg)
{
	printf("============= Config Dump =============\n");
	PRCFG_DUMP("\"%s\"", cfg->sys.cfg_file);
	PRCFG_DUMP("\"%s\"", cfg->sys.data_dir);
	PRCFG_DUMP("%u", cfg->sys.verbose_level);
	PRCFG_DUMP("%u", cfg->sys.thread);
	printf("\n");
	PRCFG_DUMP("%hhu", cfg->sock.use_encrypt);
	PRCFG_DUMP("%u", cfg->sock.type);
	PRCFG_DUMP("\"%s\"", cfg->sock.bind_addr);
	PRCFG_DUMP("%u", cfg->sock.bind_port);
	PRCFG_DUMP("%u", cfg->sock.max_conn);
	PRCFG_DUMP("%d", cfg->sock.backlog);
	PRCFG_DUMP("\"%s\"", cfg->sock.ssl_cert);
	PRCFG_DUMP("\"%s\"", cfg->sock.ssl_priv_key);
	printf("\n");
	PRCFG_DUMP("\"%s\"", cfg->iface.dev);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv4_pub);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv4);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv4_netmask);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv4_dgateway);
#ifdef TEAVPN_IPV6_SUPPORT
	PRCFG_DUMP("\"%s\"", cfg->iface.dev);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv6_pub);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv6);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv6_netmask);
	PRCFG_DUMP("\"%s\"", cfg->iface.ipv6_dgateway);
#endif
	printf("=======================================\n");
}

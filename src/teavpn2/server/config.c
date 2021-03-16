// SPDX-License-Identifier: GPL-2.0-only
/*
 *  teavpn2/server/config.c
 *
 *  Config parser for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <string.h>
#include <stdlib.h>
#include <inih/inih.h>
#include <teavpn2/lib/arena.h>
#include <teavpn2/server/common.h>


extern uint8_t __notice_level;
extern char d_srv_cfg_file[];

struct parse_struct {
	bool  		exec;
	struct_pad(0, sizeof(struct srv_cfg *) - sizeof(bool));
	struct srv_cfg	*cfg;
};

static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct parse_struct *ctx = (struct parse_struct *)user;
	struct srv_cfg *cfg = ctx->cfg;
	struct srv_sock_cfg *sock = &cfg->sock;
	struct srv_iface_cfg *iface = &cfg->iface;

	/* Section match */
	#define rmatch_s(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define rmatch_n(STR) if (unlikely(!strcmp(name, (STR))))

	rmatch_s("basic") {
		rmatch_n("data_dir") {
			cfg->data_dir = ar_strndup(value, 255);
		} else
		rmatch_n("verbose_level") {
			__notice_level = (uint8_t)atoi(value);
		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("socket") {
		rmatch_n("sock_type") {
			union {
				char		targ[4];
				uint32_t	int_rep;
			} tmp;
			tmp.int_rep = 0;
			strncpy(tmp.targ, value, sizeof(tmp.targ) - 1);
			tmp.int_rep |= 0x20202020u; /* tolower */
			tmp.targ[3]  = '\0';
			if (!memcmp(tmp.targ, "tcp", 4)) {
				sock->type = SOCK_TCP;
			} else
			if (!memcmp(tmp.targ, "udp", 4)) {
				sock->type = SOCK_UDP;
			} else {
				pr_error("Invalid socket type \"%s\"", value);
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
			sock->exposed_addr = ar_strndup(value, IPV4_L + 1);
		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("iface") {
		rmatch_n("dev") {
			iface->dev  = ar_strndup(value, 16);
		} else
		rmatch_n("mtu") {
			iface->mtu = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		rmatch_n("ipv4") {
			iface->ipv4 = ar_strndup(value, IPV4_L + 1);
		} else
		rmatch_n("ipv4_netmask") {
			iface->ipv4_netmask = ar_strndup(value, IPV4_L + 1);
#ifdef TEAVPN_IPV6_SUPPORT
		} else
		rmatch_n("ipv6") {
			iface->ipv6 = ar_strndup(value, IPV6_L + 1);
		} else
		rmatch_n("ipv6_netmask") {
			iface->ipv6_netmask = ar_strndup(value, IPV6_L + 1);
#endif
		} else {
			goto out_invalid_name;
		}
	} else {
		pr_error("Invalid section \"%s\" on line %d", section, lineno);
		goto out_err;
	}

	return true;

	#undef rmatch_n
	#undef rmatch_s
out_invalid_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d", name,
		 section, lineno);
out_err:
	ctx->exec = false;
	return false;
}


int teavpn_server_cfg_parse(struct srv_cfg *cfg)
{
	int err;
	int retval = 0;
	FILE *fhandle = NULL;
	struct parse_struct ctx;
	char *cfg_file = cfg->cfg_file;

	ctx.exec = true;
	ctx.cfg = cfg;
	if (cfg_file == NULL || *cfg_file == '\0')
		return 0;

	fhandle = fopen(cfg_file, "r");
	if (fhandle == NULL) {
		if (strcmp(cfg_file, d_srv_cfg_file) == 0)
			return 0;

		err = errno;
		pr_err("Can't open config file: \"%s\" " PRERF, cfg_file,
		       PREAR(err));
		return -err;
	}

	if (ini_parse_file(fhandle, parser_handler, &ctx) < 0) {
		retval = -1;
		goto out;
	}

	if (!ctx.exec) {
		retval = -EINVAL;
		pr_err("Error loading config file \"%s\"!", cfg_file);
		goto out;
	}


out:
	if (fhandle)
		fclose(fhandle);

	return retval;
}

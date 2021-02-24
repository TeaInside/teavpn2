
#include <string.h>
#include <stdlib.h>
#include <inih/inih.h>
#include <teavpn2/server/common.h>
#include <teavpn2/global/helpers/arena.h>
#include <teavpn2/global/helpers/string.h>

extern int8_t __notice_level;
extern char d_srv_cfg_file[];

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
	struct srv_iface_cfg *iface = &cfg->iface;

	/* Section match */
	#define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))

	RMATCH_S("basic") {
		RMATCH_N("data_dir") {
			cfg->data_dir = ar_strndup(value, 255);
		} else
		RMATCH_N("verbose_level") {
			__notice_level = (int8_t)atoi(value);
		} else {
			goto out_invalid_name;
		}
	} else
	RMATCH_S("socket") {
		RMATCH_N("sock_type") {
			union {
				char 		targ[4];
				uint32_t 	int_rep;
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
		RMATCH_N("bind_addr") {
			sock->bind_addr = ar_strndup(value, 32);
		} else
		RMATCH_N("bind_port") {
			sock->bind_port = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		RMATCH_N("max_conn") {
			sock->max_conn = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		RMATCH_N("backlog") {
			sock->backlog = (int)atoi(ar_strndup(value, 6));
		} else {
			goto out_invalid_name;
		}
	} else
	RMATCH_S("iface") {
		RMATCH_N("dev") {
			iface->dev  = ar_strndup(value, 16);
		} else
		RMATCH_N("mtu") {
			iface->mtu = (uint16_t)atoi(ar_strndup(value, 6));
		} else
		RMATCH_N("ipv4") {
			iface->ipv4 = ar_strndup(value, IPV4LEN + 1);
		} else
		RMATCH_N("ipv4_netmask") {
			iface->ipv4_netmask = ar_strndup(value, IPV4LEN + 1);
#ifdef TEAVPN_IPV6_SUPPORT
		} else
		RMATCH_N("ipv6") {
			iface->ipv6 = ar_strndup(value, IPV6LEN + 1);
		} else
		RMATCH_N("ipv6_netmask") {
			iface->ipv6_netmask = ar_strndup(value, IPV6LEN + 1);
#endif
		} else {
			goto out_invalid_name;
		}
	} else {
		pr_error("Invalid section \"%s\" on line %d", section, lineno);
		goto out_err;
	}

	return true;

	#undef RMATCH_N
	#undef RMATCH_S
out_invalid_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d", name,
		 section, lineno);
out_err:
	ctx->exec = false;
	return false;
}

int teavpn_server_cfg_parse(struct srv_cfg *cfg)
{
	FILE *fhandle = NULL;
	struct parse_struct ctx;
	char *cfg_file = cfg->cfg_file;

	ctx.exec = true;
	ctx.cfg = cfg;
	if (cfg_file == NULL || *cfg_file == '\0')
		return 0;

	fhandle = fopen(cfg_file, "r");
	if (fhandle == NULL) {
		int tmp = errno;
		if (strcmp(cfg_file, d_srv_cfg_file) == 0)
			return 0;

		pr_error("Cannot open config file: %s (%s)", cfg_file,
			 strerror(tmp));
		return -tmp;
	}
	if (ini_parse_file(fhandle, parser_handler, &ctx) < 0)
		return -1;
	if (!ctx.exec) {
		pr_error("Error loading config file!");
		return -EINVAL;
	}

	return 0;
}


#include <string.h>
#include <stdlib.h>
#include <inih/inih.h>
#include <teavpn2/lib/arena.h>
#include <teavpn2/client/common.h>


extern uint8_t __notice_level;
extern char d_cli_cfg_file[];

struct parse_struct {
	bool  		exec;
	struct cli_cfg	*cfg;
};

static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct parse_struct *ctx = (struct parse_struct *)user;
	struct cli_cfg *cfg = ctx->cfg;
	struct cli_sock_cfg *sock = &cfg->sock;
	struct cli_iface_cfg *iface = &cfg->iface;
	struct cli_auth_cfg *auth = &cfg->auth;


	/* Section match */
	#define rmatch_s(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
	#define rmatch_n(STR) if (unlikely(!strcmp(name, (STR))))

	rmatch_s("basic") {
		rmatch_n("data_dir") {
			cfg->data_dir = ar_strndup(value, 255);
		} else
		rmatch_n("verbose_level") {
			__notice_level = (int8_t)atoi(value);
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
				pr_err("Invalid socket type \"%s\"", value);
				goto out_err;
			}
		} else
		rmatch_n("server_addr") {
			sock->server_addr = ar_strndup(value, 32);
		} else
		rmatch_n("server_port") {
			sock->server_port = (uint16_t)atoi(ar_strndup(value, 6));
		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("iface") {
		rmatch_n("dev") {
			iface->dev  = ar_strndup(value, 16);
		} else {
			goto out_invalid_name;
		}
	} else
	rmatch_s("auth") {
		rmatch_n("username") {
			auth->username = ar_strndup(value, 255);
		} else
		rmatch_n("password") {
			auth->password = ar_strndup(value, 255);
		} else {
			goto out_invalid_name;
		}
	} else {
		pr_err("Invalid section \"%s\" on line %d", section, lineno);
		goto out_err;
	}

	return true;

	#undef rmatch_n
	#undef rmatch_s
out_invalid_name:
	pr_err("Invalid name \"%s\" in section \"%s\" on line %d", name,
	       section, lineno);
out_err:
	ctx->exec = false;
	return false;
}

int teavpn_client_cfg_parse(struct cli_cfg *cfg)
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
		if (strcmp(cfg_file, d_cli_cfg_file) == 0)
			return 0;

		err = errno;
		pr_err("Can't open config file: %s " PRERF, cfg_file,
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

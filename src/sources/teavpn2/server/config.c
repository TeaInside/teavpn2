
#include <string.h>
#include <stdlib.h>

#include <inih/inih.h>
#include <teavpn2/server/argv.h>
#include <teavpn2/server/entry.h>
#include <teavpn2/server/config.h>
#include <teavpn2/global/helpers/arena.h>

struct parse_struct {
	bool  		exec;
	struct srv_cfg	*cfg;
};

extern char def_cfg_file[];

static int parser_handler(void *user, const char *section, const char *name,
			  const char *value, int lineno)
{
	struct parse_struct *cx = (struct parse_struct *)user;
	struct srv_cfg *cfg = cx->cfg;

	/* Section match */
	#define RMATCH_S(STR) if (unlikely(!strcmp(section, (STR))))

	/* Name match */
  	#define RMATCH_N(STR) if (unlikely(!strcmp(name, (STR))))


	RMATCH_S("iface") {
		RMATCH_N("dev") {
			cfg->iface.dev  = ar_strndup(value, 16);
		} else
		RMATCH_N("ipv4") {
			cfg->iface.ipv4 = ar_strndup(value, IPV4LEN);
		} else
		RMATCH_N("ipv4_netmask") {
			cfg->iface.ipv4_netmask = ar_strndup(value, IPV4LEN);
		} else
		RMATCH_N("mtu") {
			cfg->iface.mtu = (uint16_t)atoi(value);
		} else {
			goto out_inv_name;
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
				cfg->sock.type = SOCK_TCP;
			} else
			if (!memcmp(tmp.targ, "udp", 4)) {
				cfg->sock.type = SOCK_UDP;
			} else {
				pr_error("Invalid socket type \"%s\"", value);
				goto out_err;
			}
		} else
		RMATCH_N("bind_addr") {
			cfg->sock.bind_addr = ar_strndup(value, 32);
		} else
		RMATCH_N("bind_port") {
			cfg->sock.bind_port = (uint16_t)atoi(value);
		} else
		RMATCH_N("backlog") {
			cfg->sock.backlog = atoi(value);
		} else {
			goto out_inv_name;
		}
	} else
	RMATCH_S("other") {
		RMATCH_N("data_dir") {
			cfg->data_dir = ar_strndup(value, 255);
		} else {
			goto out_inv_name;
		}
	} else {
		pr_error("Invalid section \"%s\" on line %d", section,
			 lineno);
		goto out_err;
	}


	#undef RMATCH_N
	#undef RMATCH_S

	return true;

out_inv_name:
	pr_error("Invalid name \"%s\" in section \"%s\" on line %d",
		 name, section, lineno);

out_err:
	cx->exec = false;
	return false;
}


int server_cfg_parse(struct srv_cfg *cfg)
{
	struct parse_struct cx;
	char *cfg_file = cfg->cfg_file;

	cx.exec = true;
	cx.cfg = cfg;

	if (cfg_file == NULL)
		return 0;

	if (ini_parse(cfg_file, parser_handler, &cx) < 0)
		return strcmp(cfg_file, def_cfg_file) ? -ENOENT : 0;

	if (!cx.exec) {
		pr_error("Error loading config file!");
		return -EINVAL;
	}

	return 0;
}
